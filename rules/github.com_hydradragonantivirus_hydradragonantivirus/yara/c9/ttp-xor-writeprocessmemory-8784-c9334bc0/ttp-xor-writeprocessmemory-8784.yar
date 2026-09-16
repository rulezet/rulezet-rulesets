rule TTP_XOR_WriteProcessMemory_8784 {
  strings:
    $key_8784 = { d0 f6 [2] e2 d4 [2] e4 e1 [2] ca e1 [2] f5 fd }

  condition:
    any of them
}