rule TTP_XOR_WriteProcessMemory_6fda {
  strings:
    $key_6fda = { 38 a8 [2] 0a 8a [2] 0c bf [2] 22 bf [2] 1d a3 }

  condition:
    any of them
}