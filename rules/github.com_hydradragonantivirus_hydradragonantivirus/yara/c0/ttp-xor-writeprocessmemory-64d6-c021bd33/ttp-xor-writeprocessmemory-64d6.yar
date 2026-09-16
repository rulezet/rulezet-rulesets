rule TTP_XOR_WriteProcessMemory_64d6 {
  strings:
    $key_64d6 = { 33 a4 [2] 01 86 [2] 07 b3 [2] 29 b3 [2] 16 af }

  condition:
    any of them
}