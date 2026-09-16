rule TTP_XOR_WriteProcessMemory_0fda {
  strings:
    $key_0fda = { 58 a8 [2] 6a 8a [2] 6c bf [2] 42 bf [2] 7d a3 }

  condition:
    any of them
}