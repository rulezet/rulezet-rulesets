rule TTP_XOR_WriteProcessMemory_45d6 {
  strings:
    $key_45d6 = { 12 a4 [2] 20 86 [2] 26 b3 [2] 08 b3 [2] 37 af }

  condition:
    any of them
}