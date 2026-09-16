rule TTP_XOR_WriteProcessMemory_ffa7 {
  strings:
    $key_ffa7 = { a8 d5 [2] 9a f7 [2] 9c c2 [2] b2 c2 [2] 8d de }

  condition:
    any of them
}