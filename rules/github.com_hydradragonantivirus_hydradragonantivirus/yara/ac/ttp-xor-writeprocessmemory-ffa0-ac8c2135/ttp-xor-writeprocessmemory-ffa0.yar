rule TTP_XOR_WriteProcessMemory_ffa0 {
  strings:
    $key_ffa0 = { a8 d2 [2] 9a f0 [2] 9c c5 [2] b2 c5 [2] 8d d9 }

  condition:
    any of them
}