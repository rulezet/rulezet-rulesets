rule TTP_XOR_WriteProcessMemory_22f5 {
  strings:
    $key_22f5 = { 75 87 [2] 47 a5 [2] 41 90 [2] 6f 90 [2] 50 8c }

  condition:
    any of them
}