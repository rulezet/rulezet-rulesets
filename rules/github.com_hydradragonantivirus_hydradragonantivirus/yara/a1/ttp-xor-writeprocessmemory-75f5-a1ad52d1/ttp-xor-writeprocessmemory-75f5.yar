rule TTP_XOR_WriteProcessMemory_75f5 {
  strings:
    $key_75f5 = { 22 87 [2] 10 a5 [2] 16 90 [2] 38 90 [2] 07 8c }

  condition:
    any of them
}