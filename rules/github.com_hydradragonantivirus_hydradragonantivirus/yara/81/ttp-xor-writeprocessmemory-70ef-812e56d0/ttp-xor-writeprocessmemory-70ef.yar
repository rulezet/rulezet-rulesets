rule TTP_XOR_WriteProcessMemory_70ef {
  strings:
    $key_70ef = { 27 9d [2] 15 bf [2] 13 8a [2] 3d 8a [2] 02 96 }

  condition:
    any of them
}