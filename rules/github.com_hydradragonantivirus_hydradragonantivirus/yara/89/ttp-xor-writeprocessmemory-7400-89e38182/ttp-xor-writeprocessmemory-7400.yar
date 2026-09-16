rule TTP_XOR_WriteProcessMemory_7400 {
  strings:
    $key_7400 = { 23 72 [2] 11 50 [2] 17 65 [2] 39 65 [2] 06 79 }

  condition:
    any of them
}