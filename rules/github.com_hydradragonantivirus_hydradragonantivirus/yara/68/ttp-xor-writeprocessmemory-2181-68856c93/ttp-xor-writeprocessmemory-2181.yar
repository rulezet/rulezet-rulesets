rule TTP_XOR_WriteProcessMemory_2181 {
  strings:
    $key_2181 = { 76 f3 [2] 44 d1 [2] 42 e4 [2] 6c e4 [2] 53 f8 }

  condition:
    any of them
}