rule TTP_XOR_WriteProcessMemory_12ef {
  strings:
    $key_12ef = { 45 9d [2] 77 bf [2] 71 8a [2] 5f 8a [2] 60 96 }

  condition:
    any of them
}