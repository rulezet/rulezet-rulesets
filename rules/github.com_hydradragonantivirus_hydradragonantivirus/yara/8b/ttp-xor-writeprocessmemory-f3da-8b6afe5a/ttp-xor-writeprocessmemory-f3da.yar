rule TTP_XOR_WriteProcessMemory_f3da {
  strings:
    $key_f3da = { a4 a8 [2] 96 8a [2] 90 bf [2] be bf [2] 81 a3 }

  condition:
    any of them
}