rule TTP_XOR_WriteProcessMemory_fe92 {
  strings:
    $key_fe92 = { a9 e0 [2] 9b c2 [2] 9d f7 [2] b3 f7 [2] 8c eb }

  condition:
    any of them
}