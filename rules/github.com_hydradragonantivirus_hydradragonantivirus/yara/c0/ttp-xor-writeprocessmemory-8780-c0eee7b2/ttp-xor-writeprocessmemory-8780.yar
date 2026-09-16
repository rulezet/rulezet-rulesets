rule TTP_XOR_WriteProcessMemory_8780 {
  strings:
    $key_8780 = { d0 f2 [2] e2 d0 [2] e4 e5 [2] ca e5 [2] f5 f9 }

  condition:
    any of them
}