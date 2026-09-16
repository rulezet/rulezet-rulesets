rule TTP_XOR_WriteProcessMemory_4cda {
  strings:
    $key_4cda = { 1b a8 [2] 29 8a [2] 2f bf [2] 01 bf [2] 3e a3 }

  condition:
    any of them
}