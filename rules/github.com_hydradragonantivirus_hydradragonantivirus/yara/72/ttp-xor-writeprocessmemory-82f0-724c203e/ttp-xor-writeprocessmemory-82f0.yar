rule TTP_XOR_WriteProcessMemory_82f0 {
  strings:
    $key_82f0 = { d5 82 [2] e7 a0 [2] e1 95 [2] cf 95 [2] f0 89 }

  condition:
    any of them
}