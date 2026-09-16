rule TTP_XOR_WriteProcessMemory_12d6 {
  strings:
    $key_12d6 = { 45 a4 [2] 77 86 [2] 71 b3 [2] 5f b3 [2] 60 af }

  condition:
    any of them
}