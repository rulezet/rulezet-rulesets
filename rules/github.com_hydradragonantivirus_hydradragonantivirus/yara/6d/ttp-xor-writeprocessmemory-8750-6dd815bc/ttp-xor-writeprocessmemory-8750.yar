rule TTP_XOR_WriteProcessMemory_8750 {
  strings:
    $key_8750 = { d0 22 [2] e2 00 [2] e4 35 [2] ca 35 [2] f5 29 }

  condition:
    any of them
}