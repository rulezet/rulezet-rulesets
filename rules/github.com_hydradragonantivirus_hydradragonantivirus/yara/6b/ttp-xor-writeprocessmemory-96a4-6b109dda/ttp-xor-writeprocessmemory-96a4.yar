rule TTP_XOR_WriteProcessMemory_96a4 {
  strings:
    $key_96a4 = { c1 d6 [2] f3 f4 [2] f5 c1 [2] db c1 [2] e4 dd }

  condition:
    any of them
}