rule TTP_XOR_WriteProcessMemory_4bda {
  strings:
    $key_4bda = { 1c a8 [2] 2e 8a [2] 28 bf [2] 06 bf [2] 39 a3 }

  condition:
    any of them
}