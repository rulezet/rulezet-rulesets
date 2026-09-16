rule TTP_XOR_WriteProcessMemory_82e0 {
  strings:
    $key_82e0 = { d5 92 [2] e7 b0 [2] e1 85 [2] cf 85 [2] f0 99 }

  condition:
    any of them
}