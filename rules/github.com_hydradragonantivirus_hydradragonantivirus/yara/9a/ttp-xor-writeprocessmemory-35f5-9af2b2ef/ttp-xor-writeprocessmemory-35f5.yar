rule TTP_XOR_WriteProcessMemory_35f5 {
  strings:
    $key_35f5 = { 62 87 [2] 50 a5 [2] 56 90 [2] 78 90 [2] 47 8c }

  condition:
    any of them
}