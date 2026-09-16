rule TTP_XOR_WriteProcessMemory_12da {
  strings:
    $key_12da = { 45 a8 [2] 77 8a [2] 71 bf [2] 5f bf [2] 60 a3 }

  condition:
    any of them
}