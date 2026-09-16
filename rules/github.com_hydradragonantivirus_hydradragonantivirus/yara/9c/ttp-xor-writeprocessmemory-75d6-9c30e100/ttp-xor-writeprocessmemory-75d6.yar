rule TTP_XOR_WriteProcessMemory_75d6 {
  strings:
    $key_75d6 = { 22 a4 [2] 10 86 [2] 16 b3 [2] 38 b3 [2] 07 af }

  condition:
    any of them
}