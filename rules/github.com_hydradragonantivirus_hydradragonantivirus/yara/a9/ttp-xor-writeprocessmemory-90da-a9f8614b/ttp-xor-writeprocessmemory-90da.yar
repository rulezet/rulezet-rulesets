rule TTP_XOR_WriteProcessMemory_90da {
  strings:
    $key_90da = { c7 a8 [2] f5 8a [2] f3 bf [2] dd bf [2] e2 a3 }

  condition:
    any of them
}