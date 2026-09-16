rule TTP_XOR_WriteProcessMemory_71f5 {
  strings:
    $key_71f5 = { 26 87 [2] 14 a5 [2] 12 90 [2] 3c 90 [2] 03 8c }

  condition:
    any of them
}