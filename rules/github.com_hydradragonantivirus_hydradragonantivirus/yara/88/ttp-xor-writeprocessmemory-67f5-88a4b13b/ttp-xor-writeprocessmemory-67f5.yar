rule TTP_XOR_WriteProcessMemory_67f5 {
  strings:
    $key_67f5 = { 30 87 [2] 02 a5 [2] 04 90 [2] 2a 90 [2] 15 8c }

  condition:
    any of them
}