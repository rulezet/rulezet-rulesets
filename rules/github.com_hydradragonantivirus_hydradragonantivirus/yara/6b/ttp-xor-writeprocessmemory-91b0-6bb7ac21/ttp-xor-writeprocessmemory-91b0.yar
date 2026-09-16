rule TTP_XOR_WriteProcessMemory_91b0 {
  strings:
    $key_91b0 = { c6 c2 [2] f4 e0 [2] f2 d5 [2] dc d5 [2] e3 c9 }

  condition:
    any of them
}