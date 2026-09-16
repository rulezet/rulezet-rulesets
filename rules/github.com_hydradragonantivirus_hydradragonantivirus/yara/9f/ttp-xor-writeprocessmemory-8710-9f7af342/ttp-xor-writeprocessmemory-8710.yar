rule TTP_XOR_WriteProcessMemory_8710 {
  strings:
    $key_8710 = { d0 62 [2] e2 40 [2] e4 75 [2] ca 75 [2] f5 69 }

  condition:
    any of them
}