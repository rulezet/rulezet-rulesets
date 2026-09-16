rule TTP_XOR_WriteProcessMemory_87a6 {
  strings:
    $key_87a6 = { d0 d4 [2] e2 f6 [2] e4 c3 [2] ca c3 [2] f5 df }

  condition:
    any of them
}