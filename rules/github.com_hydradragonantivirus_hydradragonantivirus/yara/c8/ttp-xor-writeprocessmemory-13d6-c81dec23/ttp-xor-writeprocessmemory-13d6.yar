rule TTP_XOR_WriteProcessMemory_13d6 {
  strings:
    $key_13d6 = { 44 a4 [2] 76 86 [2] 70 b3 [2] 5e b3 [2] 61 af }

  condition:
    any of them
}