rule TTP_XOR_WriteProcessMemory_1fc2 {
  strings:
    $key_1fc2 = { 48 b0 [2] 7a 92 [2] 7c a7 [2] 52 a7 [2] 6d bb }

  condition:
    any of them
}