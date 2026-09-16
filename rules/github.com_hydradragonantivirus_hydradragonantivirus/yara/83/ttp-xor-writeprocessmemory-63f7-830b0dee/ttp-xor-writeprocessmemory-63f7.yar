rule TTP_XOR_WriteProcessMemory_63f7 {
  strings:
    $key_63f7 = { 34 85 [2] 06 a7 [2] 00 92 [2] 2e 92 [2] 11 8e }

  condition:
    any of them
}