rule TTP_XOR_WriteProcessMemory_88bc {
  strings:
    $key_88bc = { df ce [2] ed ec [2] eb d9 [2] c5 d9 [2] fa c5 }

  condition:
    any of them
}