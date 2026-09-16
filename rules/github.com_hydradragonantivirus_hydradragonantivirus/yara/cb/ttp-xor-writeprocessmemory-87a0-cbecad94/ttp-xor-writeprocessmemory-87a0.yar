rule TTP_XOR_WriteProcessMemory_87a0 {
  strings:
    $key_87a0 = { d0 d2 [2] e2 f0 [2] e4 c5 [2] ca c5 [2] f5 d9 }

  condition:
    any of them
}