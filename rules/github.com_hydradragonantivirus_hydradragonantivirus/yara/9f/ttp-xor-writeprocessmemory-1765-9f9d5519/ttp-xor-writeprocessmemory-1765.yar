rule TTP_XOR_WriteProcessMemory_1765 {
  strings:
    $key_1765 = { 40 17 [2] 72 35 [2] 74 00 [2] 5a 00 [2] 65 1c }

  condition:
    any of them
}