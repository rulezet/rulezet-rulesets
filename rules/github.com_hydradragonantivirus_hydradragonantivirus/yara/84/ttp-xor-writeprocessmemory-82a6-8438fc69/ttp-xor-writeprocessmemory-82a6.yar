rule TTP_XOR_WriteProcessMemory_82a6 {
  strings:
    $key_82a6 = { d5 d4 [2] e7 f6 [2] e1 c3 [2] cf c3 [2] f0 df }

  condition:
    any of them
}