rule TTP_XOR_WriteProcessMemory_42d6 {
  strings:
    $key_42d6 = { 15 a4 [2] 27 86 [2] 21 b3 [2] 0f b3 [2] 30 af }

  condition:
    any of them
}