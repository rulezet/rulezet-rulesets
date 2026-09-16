rule TTP_XOR_WriteProcessMemory_87c3 {
  strings:
    $key_87c3 = { d0 b1 [2] e2 93 [2] e4 a6 [2] ca a6 [2] f5 ba }

  condition:
    any of them
}