rule TTP_XOR_WriteProcessMemory_fe84 {
  strings:
    $key_fe84 = { a9 f6 [2] 9b d4 [2] 9d e1 [2] b3 e1 [2] 8c fd }

  condition:
    any of them
}