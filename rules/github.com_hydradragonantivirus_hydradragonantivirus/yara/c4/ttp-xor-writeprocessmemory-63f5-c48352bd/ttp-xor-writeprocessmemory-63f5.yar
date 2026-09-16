rule TTP_XOR_WriteProcessMemory_63f5 {
  strings:
    $key_63f5 = { 34 87 [2] 06 a5 [2] 00 90 [2] 2e 90 [2] 11 8c }

  condition:
    any of them
}