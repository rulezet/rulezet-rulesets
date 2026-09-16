rule TTP_XOR_WriteProcessMemory_44ef {
  strings:
    $key_44ef = { 13 9d [2] 21 bf [2] 27 8a [2] 09 8a [2] 36 96 }

  condition:
    any of them
}