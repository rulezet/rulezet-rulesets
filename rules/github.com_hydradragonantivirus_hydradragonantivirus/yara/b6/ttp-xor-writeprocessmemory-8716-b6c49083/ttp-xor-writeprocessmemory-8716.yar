rule TTP_XOR_WriteProcessMemory_8716 {
  strings:
    $key_8716 = { d0 64 [2] e2 46 [2] e4 73 [2] ca 73 [2] f5 6f }

  condition:
    any of them
}