rule TTP_XOR_WriteProcessMemory_43d6 {
  strings:
    $key_43d6 = { 14 a4 [2] 26 86 [2] 20 b3 [2] 0e b3 [2] 31 af }

  condition:
    any of them
}