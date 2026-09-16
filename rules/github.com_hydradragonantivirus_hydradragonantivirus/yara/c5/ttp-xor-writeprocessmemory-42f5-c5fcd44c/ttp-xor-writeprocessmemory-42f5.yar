rule TTP_XOR_WriteProcessMemory_42f5 {
  strings:
    $key_42f5 = { 15 87 [2] 27 a5 [2] 21 90 [2] 0f 90 [2] 30 8c }

  condition:
    any of them
}