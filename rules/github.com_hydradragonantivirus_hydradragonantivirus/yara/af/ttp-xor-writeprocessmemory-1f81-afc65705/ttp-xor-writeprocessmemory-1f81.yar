rule TTP_XOR_WriteProcessMemory_1f81 {
  strings:
    $key_1f81 = { 48 f3 [2] 7a d1 [2] 7c e4 [2] 52 e4 [2] 6d f8 }

  condition:
    any of them
}