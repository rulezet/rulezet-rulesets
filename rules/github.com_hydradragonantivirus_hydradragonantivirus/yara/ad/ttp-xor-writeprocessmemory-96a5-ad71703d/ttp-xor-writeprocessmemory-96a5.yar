rule TTP_XOR_WriteProcessMemory_96a5 {
  strings:
    $key_96a5 = { c1 d7 [2] f3 f5 [2] f5 c0 [2] db c0 [2] e4 dc }

  condition:
    any of them
}