rule TTP_XOR_WriteProcessMemory_e1b1 {
  strings:
    $key_e1b1 = { b6 c3 [2] 84 e1 [2] 82 d4 [2] ac d4 [2] 93 c8 }

  condition:
    any of them
}