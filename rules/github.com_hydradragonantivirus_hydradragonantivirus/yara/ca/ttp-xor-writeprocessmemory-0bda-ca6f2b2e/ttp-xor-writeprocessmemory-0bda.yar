rule TTP_XOR_WriteProcessMemory_0bda {
  strings:
    $key_0bda = { 5c a8 [2] 6e 8a [2] 68 bf [2] 46 bf [2] 79 a3 }

  condition:
    any of them
}