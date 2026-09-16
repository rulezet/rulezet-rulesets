rule TTP_XOR_WriteProcessMemory_70da {
  strings:
    $key_70da = { 27 a8 [2] 15 8a [2] 13 bf [2] 3d bf [2] 02 a3 }

  condition:
    any of them
}