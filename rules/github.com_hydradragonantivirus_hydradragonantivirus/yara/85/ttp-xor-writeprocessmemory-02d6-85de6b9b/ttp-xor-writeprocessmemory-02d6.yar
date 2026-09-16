rule TTP_XOR_WriteProcessMemory_02d6 {
  strings:
    $key_02d6 = { 55 a4 [2] 67 86 [2] 61 b3 [2] 4f b3 [2] 70 af }

  condition:
    any of them
}