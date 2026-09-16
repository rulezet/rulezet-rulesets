rule TTP_XOR_WriteProcessMemory_40ef {
  strings:
    $key_40ef = { 17 9d [2] 25 bf [2] 23 8a [2] 0d 8a [2] 32 96 }

  condition:
    any of them
}