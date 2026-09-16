rule TTP_XOR_WriteProcessMemory_95da {
  strings:
    $key_95da = { c2 a8 [2] f0 8a [2] f6 bf [2] d8 bf [2] e7 a3 }

  condition:
    any of them
}