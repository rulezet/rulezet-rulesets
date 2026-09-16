rule TTP_XOR_WriteProcessMemory_e1a0 {
  strings:
    $key_e1a0 = { b6 d2 [2] 84 f0 [2] 82 c5 [2] ac c5 [2] 93 d9 }

  condition:
    any of them
}