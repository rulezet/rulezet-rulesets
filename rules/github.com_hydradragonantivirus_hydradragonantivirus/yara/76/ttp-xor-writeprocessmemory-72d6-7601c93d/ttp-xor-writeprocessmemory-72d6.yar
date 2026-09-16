rule TTP_XOR_WriteProcessMemory_72d6 {
  strings:
    $key_72d6 = { 25 a4 [2] 17 86 [2] 11 b3 [2] 3f b3 [2] 00 af }

  condition:
    any of them
}