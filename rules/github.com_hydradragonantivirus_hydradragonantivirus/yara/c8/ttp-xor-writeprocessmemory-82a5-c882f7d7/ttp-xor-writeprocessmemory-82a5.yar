rule TTP_XOR_WriteProcessMemory_82a5 {
  strings:
    $key_82a5 = { d5 d7 [2] e7 f5 [2] e1 c0 [2] cf c0 [2] f0 dc }

  condition:
    any of them
}