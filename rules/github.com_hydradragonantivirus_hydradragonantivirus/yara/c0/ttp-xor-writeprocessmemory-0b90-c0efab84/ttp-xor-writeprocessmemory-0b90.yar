rule TTP_XOR_WriteProcessMemory_0b90 {
  strings:
    $key_0b90 = { 5c e2 [2] 6e c0 [2] 68 f5 [2] 46 f5 [2] 79 e9 }

  condition:
    any of them
}