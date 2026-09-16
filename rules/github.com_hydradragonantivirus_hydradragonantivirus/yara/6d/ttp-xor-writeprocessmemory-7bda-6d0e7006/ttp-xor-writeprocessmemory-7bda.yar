rule TTP_XOR_WriteProcessMemory_7bda {
  strings:
    $key_7bda = { 2c a8 [2] 1e 8a [2] 18 bf [2] 36 bf [2] 09 a3 }

  condition:
    any of them
}