rule TTP_XOR_WriteProcessMemory_61ef {
  strings:
    $key_61ef = { 36 9d [2] 04 bf [2] 02 8a [2] 2c 8a [2] 13 96 }

  condition:
    any of them
}