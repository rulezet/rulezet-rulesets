rule TTP_XOR_WriteProcessMemory_8767 {
  strings:
    $key_8767 = { d0 15 [2] e2 37 [2] e4 02 [2] ca 02 [2] f5 1e }

  condition:
    any of them
}