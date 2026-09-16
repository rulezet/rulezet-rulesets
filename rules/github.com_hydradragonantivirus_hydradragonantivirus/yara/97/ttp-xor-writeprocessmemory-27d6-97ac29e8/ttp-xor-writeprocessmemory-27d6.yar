rule TTP_XOR_WriteProcessMemory_27d6 {
  strings:
    $key_27d6 = { 70 a4 [2] 42 86 [2] 44 b3 [2] 6a b3 [2] 55 af }

  condition:
    any of them
}