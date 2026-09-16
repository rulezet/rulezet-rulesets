rule TTP_XOR_WriteProcessMemory_4b90 {
  strings:
    $key_4b90 = { 1c e2 [2] 2e c0 [2] 28 f5 [2] 06 f5 [2] 39 e9 }

  condition:
    any of them
}