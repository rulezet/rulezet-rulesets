rule TTP_XOR_WriteProcessMemory_fe81 {
  strings:
    $key_fe81 = { a9 f3 [2] 9b d1 [2] 9d e4 [2] b3 e4 [2] 8c f8 }

  condition:
    any of them
}