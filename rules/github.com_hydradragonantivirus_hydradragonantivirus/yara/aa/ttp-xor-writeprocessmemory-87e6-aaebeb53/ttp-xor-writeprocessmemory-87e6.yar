rule TTP_XOR_WriteProcessMemory_87e6 {
  strings:
    $key_87e6 = { d0 94 [2] e2 b6 [2] e4 83 [2] ca 83 [2] f5 9f }

  condition:
    any of them
}