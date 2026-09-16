rule TTP_XOR_WriteProcessMemory_88b3 {
  strings:
    $key_88b3 = { df c1 [2] ed e3 [2] eb d6 [2] c5 d6 [2] fa ca }

  condition:
    any of them
}