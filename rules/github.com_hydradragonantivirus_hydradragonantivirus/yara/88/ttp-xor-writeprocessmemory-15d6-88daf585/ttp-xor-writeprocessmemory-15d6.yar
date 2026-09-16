rule TTP_XOR_WriteProcessMemory_15d6 {
  strings:
    $key_15d6 = { 42 a4 [2] 70 86 [2] 76 b3 [2] 58 b3 [2] 67 af }

  condition:
    any of them
}