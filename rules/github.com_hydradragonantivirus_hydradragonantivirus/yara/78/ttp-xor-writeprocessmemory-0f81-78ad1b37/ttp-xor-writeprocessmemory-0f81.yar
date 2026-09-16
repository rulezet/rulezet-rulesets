rule TTP_XOR_WriteProcessMemory_0f81 {
  strings:
    $key_0f81 = { 58 f3 [2] 6a d1 [2] 6c e4 [2] 42 e4 [2] 7d f8 }

  condition:
    any of them
}