rule TTP_XOR_WriteProcessMemory_10ef {
  strings:
    $key_10ef = { 47 9d [2] 75 bf [2] 73 8a [2] 5d 8a [2] 62 96 }

  condition:
    any of them
}