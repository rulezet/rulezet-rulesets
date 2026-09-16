rule TTP_XOR_WriteProcessMemory_25ef {
  strings:
    $key_25ef = { 72 9d [2] 40 bf [2] 46 8a [2] 68 8a [2] 57 96 }

  condition:
    any of them
}