rule TTP_XOR_WriteProcessMemory_88b2 {
  strings:
    $key_88b2 = { df c0 [2] ed e2 [2] eb d7 [2] c5 d7 [2] fa cb }

  condition:
    any of them
}