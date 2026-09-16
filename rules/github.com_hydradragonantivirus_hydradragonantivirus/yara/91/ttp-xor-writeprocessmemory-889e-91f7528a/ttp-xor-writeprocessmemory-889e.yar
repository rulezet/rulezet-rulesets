rule TTP_XOR_WriteProcessMemory_889e {
  strings:
    $key_889e = { df ec [2] ed ce [2] eb fb [2] c5 fb [2] fa e7 }

  condition:
    any of them
}