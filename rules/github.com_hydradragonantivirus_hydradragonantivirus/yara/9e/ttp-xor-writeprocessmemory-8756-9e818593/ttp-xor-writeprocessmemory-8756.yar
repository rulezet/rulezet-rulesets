rule TTP_XOR_WriteProcessMemory_8756 {
  strings:
    $key_8756 = { d0 24 [2] e2 06 [2] e4 33 [2] ca 33 [2] f5 2f }

  condition:
    any of them
}