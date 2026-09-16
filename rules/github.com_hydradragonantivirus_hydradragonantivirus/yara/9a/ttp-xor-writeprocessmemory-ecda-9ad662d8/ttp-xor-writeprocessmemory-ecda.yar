rule TTP_XOR_WriteProcessMemory_ecda {
  strings:
    $key_ecda = { bb a8 [2] 89 8a [2] 8f bf [2] a1 bf [2] 9e a3 }

  condition:
    any of them
}