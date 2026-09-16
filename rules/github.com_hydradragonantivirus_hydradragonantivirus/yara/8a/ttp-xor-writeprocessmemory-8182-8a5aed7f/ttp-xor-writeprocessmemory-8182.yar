rule TTP_XOR_WriteProcessMemory_8182 {
  strings:
    $key_8182 = { d6 f0 [2] e4 d2 [2] e2 e7 [2] cc e7 [2] f3 fb }

  condition:
    any of them
}