rule TTP_XOR_WriteProcessMemory_8770 {
  strings:
    $key_8770 = { d0 02 [2] e2 20 [2] e4 15 [2] ca 15 [2] f5 09 }

  condition:
    any of them
}