rule TTP_XOR_WriteProcessMemory_1751 {
  strings:
    $key_1751 = { 40 23 [2] 72 01 [2] 74 34 [2] 5a 34 [2] 65 28 }

  condition:
    any of them
}