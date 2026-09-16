rule TTP_XOR_WriteProcessMemory_feda {
  strings:
    $key_feda = { a9 a8 [2] 9b 8a [2] 9d bf [2] b3 bf [2] 8c a3 }

  condition:
    any of them
}