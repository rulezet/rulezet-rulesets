rule TTP_XOR_WriteProcessMemory_40da {
  strings:
    $key_40da = { 17 a8 [2] 25 8a [2] 23 bf [2] 0d bf [2] 32 a3 }

  condition:
    any of them
}