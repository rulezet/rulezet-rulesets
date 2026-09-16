rule TTP_XOR_WriteProcessMemory_37ef {
  strings:
    $key_37ef = { 60 9d [2] 52 bf [2] 54 8a [2] 7a 8a [2] 45 96 }

  condition:
    any of them
}