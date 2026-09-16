rule TTP_XOR_WriteProcessMemory_4eda {
  strings:
    $key_4eda = { 19 a8 [2] 2b 8a [2] 2d bf [2] 03 bf [2] 3c a3 }

  condition:
    any of them
}