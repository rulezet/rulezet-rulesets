rule TTP_XOR_WriteProcessMemory_75f6 {
  strings:
    $key_75f6 = { 22 84 [2] 10 a6 [2] 16 93 [2] 38 93 [2] 07 8f }

  condition:
    any of them
}