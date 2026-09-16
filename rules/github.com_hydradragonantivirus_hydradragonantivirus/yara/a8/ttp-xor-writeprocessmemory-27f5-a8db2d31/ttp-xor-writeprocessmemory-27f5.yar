rule TTP_XOR_WriteProcessMemory_27f5 {
  strings:
    $key_27f5 = { 70 87 [2] 42 a5 [2] 44 90 [2] 6a 90 [2] 55 8c }

  condition:
    any of them
}