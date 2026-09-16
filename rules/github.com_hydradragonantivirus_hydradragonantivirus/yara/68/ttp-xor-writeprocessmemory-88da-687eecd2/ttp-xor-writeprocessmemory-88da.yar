rule TTP_XOR_WriteProcessMemory_88da {
  strings:
    $key_88da = { df a8 [2] ed 8a [2] eb bf [2] c5 bf [2] fa a3 }

  condition:
    any of them
}