rule TTP_XOR_WriteProcessMemory_8760 {
  strings:
    $key_8760 = { d0 12 [2] e2 30 [2] e4 05 [2] ca 05 [2] f5 19 }

  condition:
    any of them
}