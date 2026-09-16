rule TTP_XOR_WriteProcessMemory_64f5 {
  strings:
    $key_64f5 = { 33 87 [2] 01 a5 [2] 07 90 [2] 29 90 [2] 16 8c }

  condition:
    any of them
}