rule TTP_XOR_WriteProcessMemory_23d6 {
  strings:
    $key_23d6 = { 74 a4 [2] 46 86 [2] 40 b3 [2] 6e b3 [2] 51 af }

  condition:
    any of them
}