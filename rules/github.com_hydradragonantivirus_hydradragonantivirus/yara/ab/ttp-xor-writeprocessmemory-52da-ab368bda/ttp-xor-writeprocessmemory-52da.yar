rule TTP_XOR_WriteProcessMemory_52da {
  strings:
    $key_52da = { 05 a8 [2] 37 8a [2] 31 bf [2] 1f bf [2] 20 a3 }

  condition:
    any of them
}