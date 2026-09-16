rule TTP_XOR_WriteProcessMemory_6325 {
  strings:
    $key_6325 = { 34 57 [2] 06 75 [2] 00 40 [2] 2e 40 [2] 11 5c }

  condition:
    any of them
}