rule TTP_XOR_WriteProcessMemory_2cda {
  strings:
    $key_2cda = { 7b a8 [2] 49 8a [2] 4f bf [2] 61 bf [2] 5e a3 }

  condition:
    any of them
}