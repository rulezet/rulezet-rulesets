rule TTP_XOR_WriteProcessMemory_1700 {
  strings:
    $key_1700 = { 40 72 [2] 72 50 [2] 74 65 [2] 5a 65 [2] 65 79 }

  condition:
    any of them
}