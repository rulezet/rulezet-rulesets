rule TTP_XOR_WriteProcessMemory_7425 {
  strings:
    $key_7425 = { 23 57 [2] 11 75 [2] 17 40 [2] 39 40 [2] 06 5c }

  condition:
    any of them
}