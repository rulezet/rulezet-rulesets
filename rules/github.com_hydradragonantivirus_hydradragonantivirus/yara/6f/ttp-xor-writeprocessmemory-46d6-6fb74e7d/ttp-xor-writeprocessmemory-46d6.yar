rule TTP_XOR_WriteProcessMemory_46d6 {
  strings:
    $key_46d6 = { 11 a4 [2] 23 86 [2] 25 b3 [2] 0b b3 [2] 34 af }

  condition:
    any of them
}