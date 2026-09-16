rule TTP_XOR_WriteProcessMemory_15da {
  strings:
    $key_15da = { 42 a8 [2] 70 8a [2] 76 bf [2] 58 bf [2] 67 a3 }

  condition:
    any of them
}