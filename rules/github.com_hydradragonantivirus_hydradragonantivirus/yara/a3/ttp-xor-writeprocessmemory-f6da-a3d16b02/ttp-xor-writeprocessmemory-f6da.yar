rule TTP_XOR_WriteProcessMemory_f6da {
  strings:
    $key_f6da = { a1 a8 [2] 93 8a [2] 95 bf [2] bb bf [2] 84 a3 }

  condition:
    any of them
}