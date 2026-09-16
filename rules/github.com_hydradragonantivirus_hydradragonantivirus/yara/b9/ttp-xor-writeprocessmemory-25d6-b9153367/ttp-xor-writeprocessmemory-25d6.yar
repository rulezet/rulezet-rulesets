rule TTP_XOR_WriteProcessMemory_25d6 {
  strings:
    $key_25d6 = { 72 a4 [2] 40 86 [2] 46 b3 [2] 68 b3 [2] 57 af }

  condition:
    any of them
}