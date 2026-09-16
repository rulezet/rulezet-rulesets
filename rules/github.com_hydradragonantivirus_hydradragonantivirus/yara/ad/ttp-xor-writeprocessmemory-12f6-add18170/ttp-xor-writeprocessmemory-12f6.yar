rule TTP_XOR_WriteProcessMemory_12f6 {
  strings:
    $key_12f6 = { 45 84 [2] 77 a6 [2] 71 93 [2] 5f 93 [2] 60 8f }

  condition:
    any of them
}