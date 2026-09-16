rule TTP_XOR_WriteProcessMemory_35d6 {
  strings:
    $key_35d6 = { 62 a4 [2] 50 86 [2] 56 b3 [2] 78 b3 [2] 47 af }

  condition:
    any of them
}