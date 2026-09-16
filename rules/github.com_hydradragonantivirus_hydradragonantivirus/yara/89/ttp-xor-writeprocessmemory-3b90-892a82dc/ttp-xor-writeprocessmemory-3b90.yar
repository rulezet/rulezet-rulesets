rule TTP_XOR_WriteProcessMemory_3b90 {
  strings:
    $key_3b90 = { 6c e2 [2] 5e c0 [2] 58 f5 [2] 76 f5 [2] 49 e9 }

  condition:
    any of them
}