rule TTP_XOR_WriteProcessMemory_8763 {
  strings:
    $key_8763 = { d0 11 [2] e2 33 [2] e4 06 [2] ca 06 [2] f5 1a }

  condition:
    any of them
}