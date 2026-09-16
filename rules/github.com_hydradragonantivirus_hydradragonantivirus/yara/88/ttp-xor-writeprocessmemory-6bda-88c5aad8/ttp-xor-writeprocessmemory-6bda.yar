rule TTP_XOR_WriteProcessMemory_6bda {
  strings:
    $key_6bda = { 3c a8 [2] 0e 8a [2] 08 bf [2] 26 bf [2] 19 a3 }

  condition:
    any of them
}