rule TTP_XOR_WriteProcessMemory_20ef {
  strings:
    $key_20ef = { 77 9d [2] 45 bf [2] 43 8a [2] 6d 8a [2] 52 96 }

  condition:
    any of them
}