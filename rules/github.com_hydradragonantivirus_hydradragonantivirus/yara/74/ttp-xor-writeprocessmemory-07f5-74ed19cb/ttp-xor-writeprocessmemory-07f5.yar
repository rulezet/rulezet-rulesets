rule TTP_XOR_WriteProcessMemory_07f5 {
  strings:
    $key_07f5 = { 50 87 [2] 62 a5 [2] 64 90 [2] 4a 90 [2] 75 8c }

  condition:
    any of them
}