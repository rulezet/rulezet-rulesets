rule TTP_XOR_WriteProcessMemory_82e1 {
  strings:
    $key_82e1 = { d5 93 [2] e7 b1 [2] e1 84 [2] cf 84 [2] f0 98 }

  condition:
    any of them
}