rule TTP_XOR_WriteProcessMemory_50f5 {
  strings:
    $key_50f5 = { 07 87 [2] 35 a5 [2] 33 90 [2] 1d 90 [2] 22 8c }

  condition:
    any of them
}