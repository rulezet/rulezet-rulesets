rule TTP_XOR_WriteProcessMemory_44da {
  strings:
    $key_44da = { 13 a8 [2] 21 8a [2] 27 bf [2] 09 bf [2] 36 a3 }

  condition:
    any of them
}