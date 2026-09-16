rule TTP_XOR_WriteProcessMemory_ecef {
  strings:
    $key_ecef = { bb 9d [2] 89 bf [2] 8f 8a [2] a1 8a [2] 9e 96 }

  condition:
    any of them
}