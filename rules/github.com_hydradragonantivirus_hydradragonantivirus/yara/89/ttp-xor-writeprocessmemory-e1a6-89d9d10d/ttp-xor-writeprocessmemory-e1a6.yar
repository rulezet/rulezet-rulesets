rule TTP_XOR_WriteProcessMemory_e1a6 {
  strings:
    $key_e1a6 = { b6 d4 [2] 84 f6 [2] 82 c3 [2] ac c3 [2] 93 df }

  condition:
    any of them
}