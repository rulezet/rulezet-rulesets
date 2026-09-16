rule TTP_XOR_WriteProcessMemory_25f5 {
  strings:
    $key_25f5 = { 72 87 [2] 40 a5 [2] 46 90 [2] 68 90 [2] 57 8c }

  condition:
    any of them
}