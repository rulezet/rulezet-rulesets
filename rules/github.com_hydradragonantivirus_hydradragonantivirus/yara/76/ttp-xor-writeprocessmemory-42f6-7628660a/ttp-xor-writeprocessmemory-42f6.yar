rule TTP_XOR_WriteProcessMemory_42f6 {
  strings:
    $key_42f6 = { 15 84 [2] 27 a6 [2] 21 93 [2] 0f 93 [2] 30 8f }

  condition:
    any of them
}