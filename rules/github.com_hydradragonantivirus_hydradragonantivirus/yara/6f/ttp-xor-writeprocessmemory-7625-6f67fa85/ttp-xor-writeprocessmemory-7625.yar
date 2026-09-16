rule TTP_XOR_WriteProcessMemory_7625 {
  strings:
    $key_7625 = { 21 57 [2] 13 75 [2] 15 40 [2] 3b 40 [2] 04 5c }

  condition:
    any of them
}