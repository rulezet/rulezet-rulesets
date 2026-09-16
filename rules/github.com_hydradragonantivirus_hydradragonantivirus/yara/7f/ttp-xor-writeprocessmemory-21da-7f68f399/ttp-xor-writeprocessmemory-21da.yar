rule TTP_XOR_WriteProcessMemory_21da {
  strings:
    $key_21da = { 76 a8 [2] 44 8a [2] 42 bf [2] 6c bf [2] 53 a3 }

  condition:
    any of them
}