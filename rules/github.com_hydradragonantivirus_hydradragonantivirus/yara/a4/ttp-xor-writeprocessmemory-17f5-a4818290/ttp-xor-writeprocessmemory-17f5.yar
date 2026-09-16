rule TTP_XOR_WriteProcessMemory_17f5 {
  strings:
    $key_17f5 = { 40 87 [2] 72 a5 [2] 74 90 [2] 5a 90 [2] 65 8c }

  condition:
    any of them
}