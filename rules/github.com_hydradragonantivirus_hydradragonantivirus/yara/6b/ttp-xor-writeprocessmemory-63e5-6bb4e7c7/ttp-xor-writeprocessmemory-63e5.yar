rule TTP_XOR_WriteProcessMemory_63e5 {
  strings:
    $key_63e5 = { 34 97 [2] 06 b5 [2] 00 80 [2] 2e 80 [2] 11 9c }

  condition:
    any of them
}