rule TTP_XOR_WriteProcessMemory_34ef {
  strings:
    $key_34ef = { 63 9d [2] 51 bf [2] 57 8a [2] 79 8a [2] 46 96 }

  condition:
    any of them
}