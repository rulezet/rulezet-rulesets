rule TTP_XOR_WriteProcessMemory_f5d6 {
  strings:
    $key_f5d6 = { a2 a4 [2] 90 86 [2] 96 b3 [2] b8 b3 [2] 87 af }

  condition:
    any of them
}