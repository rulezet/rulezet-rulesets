rule TTP_XOR_WriteProcessMemory_87c1 {
  strings:
    $key_87c1 = { d0 b3 [2] e2 91 [2] e4 a4 [2] ca a4 [2] f5 b8 }

  condition:
    any of them
}