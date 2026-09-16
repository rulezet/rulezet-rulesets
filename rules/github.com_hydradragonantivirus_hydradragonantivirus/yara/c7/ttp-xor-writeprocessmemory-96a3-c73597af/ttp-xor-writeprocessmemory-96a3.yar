rule TTP_XOR_WriteProcessMemory_96a3 {
  strings:
    $key_96a3 = { c1 d1 [2] f3 f3 [2] f5 c6 [2] db c6 [2] e4 da }

  condition:
    any of them
}