rule TTP_XOR_WriteProcessMemory_e1a1 {
  strings:
    $key_e1a1 = { b6 d3 [2] 84 f1 [2] 82 c4 [2] ac c4 [2] 93 d8 }

  condition:
    any of them
}