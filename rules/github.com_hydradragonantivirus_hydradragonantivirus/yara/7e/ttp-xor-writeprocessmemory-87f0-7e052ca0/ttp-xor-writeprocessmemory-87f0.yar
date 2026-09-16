rule TTP_XOR_WriteProcessMemory_87f0 {
  strings:
    $key_87f0 = { d0 82 [2] e2 a0 [2] e4 95 [2] ca 95 [2] f5 89 }

  condition:
    any of them
}