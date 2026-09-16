rule TTP_XOR_WriteProcessMemory_65f5 {
  strings:
    $key_65f5 = { 32 87 [2] 00 a5 [2] 06 90 [2] 28 90 [2] 17 8c }

  condition:
    any of them
}