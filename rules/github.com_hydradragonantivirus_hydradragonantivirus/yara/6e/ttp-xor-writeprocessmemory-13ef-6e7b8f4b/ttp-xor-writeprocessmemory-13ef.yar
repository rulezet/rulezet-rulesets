rule TTP_XOR_WriteProcessMemory_13ef {
  strings:
    $key_13ef = { 44 9d [2] 76 bf [2] 70 8a [2] 5e 8a [2] 61 96 }

  condition:
    any of them
}