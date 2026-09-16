rule TTP_XOR_WriteProcessMemory_50da {
  strings:
    $key_50da = { 07 a8 [2] 35 8a [2] 33 bf [2] 1d bf [2] 22 a3 }

  condition:
    any of them
}