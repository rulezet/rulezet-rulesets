rule TTP_XOR_WriteProcessMemory_88b5 {
  strings:
    $key_88b5 = { df c7 [2] ed e5 [2] eb d0 [2] c5 d0 [2] fa cc }

  condition:
    any of them
}