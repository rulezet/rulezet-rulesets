rule TTP_XOR_WriteProcessMemory_8752 {
  strings:
    $key_8752 = { d0 20 [2] e2 02 [2] e4 37 [2] ca 37 [2] f5 2b }

  condition:
    any of them
}