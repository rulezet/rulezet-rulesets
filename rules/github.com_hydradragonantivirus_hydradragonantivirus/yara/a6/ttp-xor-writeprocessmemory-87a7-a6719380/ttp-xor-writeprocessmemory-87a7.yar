rule TTP_XOR_WriteProcessMemory_87a7 {
  strings:
    $key_87a7 = { d0 d5 [2] e2 f7 [2] e4 c2 [2] ca c2 [2] f5 de }

  condition:
    any of them
}