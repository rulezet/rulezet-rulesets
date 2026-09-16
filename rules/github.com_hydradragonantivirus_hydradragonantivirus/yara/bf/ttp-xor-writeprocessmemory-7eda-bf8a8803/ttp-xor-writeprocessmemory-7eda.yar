rule TTP_XOR_WriteProcessMemory_7eda {
  strings:
    $key_7eda = { 29 a8 [2] 1b 8a [2] 1d bf [2] 33 bf [2] 0c a3 }

  condition:
    any of them
}