rule TTP_XOR_WriteProcessMemory_8751 {
  strings:
    $key_8751 = { d0 23 [2] e2 01 [2] e4 34 [2] ca 34 [2] f5 28 }

  condition:
    any of them
}