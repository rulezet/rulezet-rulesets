rule TTP_XOR_WriteProcessMemory_46f5 {
  strings:
    $key_46f5 = { 11 87 [2] 23 a5 [2] 25 90 [2] 0b 90 [2] 34 8c }

  condition:
    any of them
}