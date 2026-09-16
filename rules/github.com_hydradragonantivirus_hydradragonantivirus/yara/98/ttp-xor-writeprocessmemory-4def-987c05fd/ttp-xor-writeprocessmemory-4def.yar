rule TTP_XOR_WriteProcessMemory_4def {
  strings:
    $key_4def = { 1a 9d [2] 28 bf [2] 2e 8a [2] 00 8a [2] 3f 96 }

  condition:
    any of them
}