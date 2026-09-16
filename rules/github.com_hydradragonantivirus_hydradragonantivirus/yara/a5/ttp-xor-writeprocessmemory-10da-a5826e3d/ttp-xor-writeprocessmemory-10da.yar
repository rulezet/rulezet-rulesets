rule TTP_XOR_WriteProcessMemory_10da {
  strings:
    $key_10da = { 47 a8 [2] 75 8a [2] 73 bf [2] 5d bf [2] 62 a3 }

  condition:
    any of them
}