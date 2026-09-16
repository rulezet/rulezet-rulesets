rule TTP_XOR_WriteProcessMemory_1165 {
  strings:
    $key_1165 = { 46 17 [2] 74 35 [2] 72 00 [2] 5c 00 [2] 63 1c }

  condition:
    any of them
}