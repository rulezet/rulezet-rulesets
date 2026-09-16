rule TTP_XOR_WriteProcessMemory_8742 {
  strings:
    $key_8742 = { d0 30 [2] e2 12 [2] e4 27 [2] ca 27 [2] f5 3b }

  condition:
    any of them
}