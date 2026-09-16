rule TTP_XOR_WriteProcessMemory_13f5 {
  strings:
    $key_13f5 = { 44 87 [2] 76 a5 [2] 70 90 [2] 5e 90 [2] 61 8c }

  condition:
    any of them
}