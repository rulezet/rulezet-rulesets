rule TTP_XOR_WriteProcessMemory_93da {
  strings:
    $key_93da = { c4 a8 [2] f6 8a [2] f0 bf [2] de bf [2] e1 a3 }

  condition:
    any of them
}