rule TTP_XOR_WriteProcessMemory_e1a7 {
  strings:
    $key_e1a7 = { b6 d5 [2] 84 f7 [2] 82 c2 [2] ac c2 [2] 93 de }

  condition:
    any of them
}