rule TTP_XOR_WriteProcessMemory_75da {
  strings:
    $key_75da = { 22 a8 [2] 10 8a [2] 16 bf [2] 38 bf [2] 07 a3 }

  condition:
    any of them
}