rule TTP_XOR_WriteProcessMemory_5dda {
  strings:
    $key_5dda = { 0a a8 [2] 38 8a [2] 3e bf [2] 10 bf [2] 2f a3 }

  condition:
    any of them
}