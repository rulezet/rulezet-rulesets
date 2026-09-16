rule TTP_XOR_WriteProcessMemory_2eda {
  strings:
    $key_2eda = { 79 a8 [2] 4b 8a [2] 4d bf [2] 63 bf [2] 5c a3 }

  condition:
    any of them
}