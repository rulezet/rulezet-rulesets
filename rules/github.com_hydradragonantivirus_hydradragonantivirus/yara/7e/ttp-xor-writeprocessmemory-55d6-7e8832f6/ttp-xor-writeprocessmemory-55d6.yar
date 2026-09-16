rule TTP_XOR_WriteProcessMemory_55d6 {
  strings:
    $key_55d6 = { 02 a4 [2] 30 86 [2] 36 b3 [2] 18 b3 [2] 27 af }

  condition:
    any of them
}