rule TTP_XOR_WriteProcessMemory_e1a5 {
  strings:
    $key_e1a5 = { b6 d7 [2] 84 f5 [2] 82 c0 [2] ac c0 [2] 93 dc }

  condition:
    any of them
}