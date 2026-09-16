rule TTP_XOR_WriteProcessMemory_6375 {
  strings:
    $key_6375 = { 34 07 [2] 06 25 [2] 00 10 [2] 2e 10 [2] 11 0c }

  condition:
    any of them
}