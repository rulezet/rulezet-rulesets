rule TTP_XOR_WriteProcessMemory_62da {
  strings:
    $key_62da = { 35 a8 [2] 07 8a [2] 01 bf [2] 2f bf [2] 10 a3 }

  condition:
    any of them
}