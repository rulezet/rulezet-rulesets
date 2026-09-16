rule TTP_XOR_WriteProcessMemory_63f2 {
  strings:
    $key_63f2 = { 34 80 [2] 06 a2 [2] 00 97 [2] 2e 97 [2] 11 8b }

  condition:
    any of them
}