rule TTP_XOR_WriteProcessMemory_3084 {
  strings:
    $key_3084 = { 67 f6 [2] 55 d4 [2] 53 e1 [2] 7d e1 [2] 42 fd }

  condition:
    any of them
}