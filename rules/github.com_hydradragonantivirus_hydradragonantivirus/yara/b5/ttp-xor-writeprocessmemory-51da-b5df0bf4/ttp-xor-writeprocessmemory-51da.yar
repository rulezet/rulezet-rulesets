rule TTP_XOR_WriteProcessMemory_51da {
  strings:
    $key_51da = { 06 a8 [2] 34 8a [2] 32 bf [2] 1c bf [2] 23 a3 }

  condition:
    any of them
}