rule TTP_XOR_WriteProcessMemory_4ada {
  strings:
    $key_4ada = { 1d a8 [2] 2f 8a [2] 29 bf [2] 07 bf [2] 38 a3 }

  condition:
    any of them
}