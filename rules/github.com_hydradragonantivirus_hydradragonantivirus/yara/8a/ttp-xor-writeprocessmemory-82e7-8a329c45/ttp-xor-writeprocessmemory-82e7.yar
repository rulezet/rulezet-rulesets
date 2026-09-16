rule TTP_XOR_WriteProcessMemory_82e7 {
  strings:
    $key_82e7 = { d5 95 [2] e7 b7 [2] e1 82 [2] cf 82 [2] f0 9e }

  condition:
    any of them
}