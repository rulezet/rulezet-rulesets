rule TTP_XOR_WriteProcessMemory_e1a2 {
  strings:
    $key_e1a2 = { b6 d0 [2] 84 f2 [2] 82 c7 [2] ac c7 [2] 93 db }

  condition:
    any of them
}