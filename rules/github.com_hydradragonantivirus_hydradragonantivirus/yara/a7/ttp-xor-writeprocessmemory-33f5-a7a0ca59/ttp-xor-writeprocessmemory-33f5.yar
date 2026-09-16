rule TTP_XOR_WriteProcessMemory_33f5 {
  strings:
    $key_33f5 = { 64 87 [2] 56 a5 [2] 50 90 [2] 7e 90 [2] 41 8c }

  condition:
    any of them
}