rule TTP_XOR_WriteProcessMemory_71ef {
  strings:
    $key_71ef = { 26 9d [2] 14 bf [2] 12 8a [2] 3c 8a [2] 03 96 }

  condition:
    any of them
}