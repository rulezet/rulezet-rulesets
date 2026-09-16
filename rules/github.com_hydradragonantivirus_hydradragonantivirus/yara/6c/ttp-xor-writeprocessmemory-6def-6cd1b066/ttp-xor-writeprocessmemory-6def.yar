rule TTP_XOR_WriteProcessMemory_6def {
  strings:
    $key_6def = { 3a 9d [2] 08 bf [2] 0e 8a [2] 20 8a [2] 1f 96 }

  condition:
    any of them
}