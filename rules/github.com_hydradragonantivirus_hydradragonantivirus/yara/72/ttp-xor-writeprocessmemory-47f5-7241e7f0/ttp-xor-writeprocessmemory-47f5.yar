rule TTP_XOR_WriteProcessMemory_47f5 {
  strings:
    $key_47f5 = { 10 87 [2] 22 a5 [2] 24 90 [2] 0a 90 [2] 35 8c }

  condition:
    any of them
}