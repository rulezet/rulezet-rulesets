rule TTP_XOR_WriteProcessMemory_3bda {
  strings:
    $key_3bda = { 6c a8 [2] 5e 8a [2] 58 bf [2] 76 bf [2] 49 a3 }

  condition:
    any of them
}