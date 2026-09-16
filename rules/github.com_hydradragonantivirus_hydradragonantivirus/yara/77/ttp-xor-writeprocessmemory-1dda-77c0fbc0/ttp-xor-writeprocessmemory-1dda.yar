rule TTP_XOR_WriteProcessMemory_1dda {
  strings:
    $key_1dda = { 4a a8 [2] 78 8a [2] 7e bf [2] 50 bf [2] 6f a3 }

  condition:
    any of them
}