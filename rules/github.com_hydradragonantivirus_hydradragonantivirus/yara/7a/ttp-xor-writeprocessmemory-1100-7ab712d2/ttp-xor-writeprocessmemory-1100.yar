rule TTP_XOR_WriteProcessMemory_1100 {
  strings:
    $key_1100 = { 46 72 [2] 74 50 [2] 72 65 [2] 5c 65 [2] 63 79 }

  condition:
    any of them
}