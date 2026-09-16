rule TTP_XOR_WriteProcessMemory_76f5 {
  strings:
    $key_76f5 = { 21 87 [2] 13 a5 [2] 15 90 [2] 3b 90 [2] 04 8c }

  condition:
    any of them
}