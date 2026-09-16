rule TTP_XOR_WriteProcessMemory_5bda {
  strings:
    $key_5bda = { 0c a8 [2] 3e 8a [2] 38 bf [2] 16 bf [2] 29 a3 }

  condition:
    any of them
}