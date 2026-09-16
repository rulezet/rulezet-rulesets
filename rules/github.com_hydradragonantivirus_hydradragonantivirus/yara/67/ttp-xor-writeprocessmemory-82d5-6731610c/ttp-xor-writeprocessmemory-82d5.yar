rule TTP_XOR_WriteProcessMemory_82d5 {
  strings:
    $key_82d5 = { d5 a7 [2] e7 85 [2] e1 b0 [2] cf b0 [2] f0 ac }

  condition:
    any of them
}