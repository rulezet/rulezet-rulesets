rule TTP_XOR_WriteProcessMemory_87f6 {
  strings:
    $key_87f6 = { d0 84 [2] e2 a6 [2] e4 93 [2] ca 93 [2] f5 8f }

  condition:
    any of them
}