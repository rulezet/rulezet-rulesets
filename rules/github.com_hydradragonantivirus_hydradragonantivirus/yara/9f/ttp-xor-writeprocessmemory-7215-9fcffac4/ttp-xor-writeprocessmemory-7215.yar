rule TTP_XOR_WriteProcessMemory_7215 {
  strings:
    $key_7215 = { 25 67 [2] 17 45 [2] 11 70 [2] 3f 70 [2] 00 6c }

  condition:
    any of them
}