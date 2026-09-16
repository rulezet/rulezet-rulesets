rule TTP_XOR_WriteProcessMemory_33f6 {
  strings:
    $key_33f6 = { 64 84 [2] 56 a6 [2] 50 93 [2] 7e 93 [2] 41 8f }

  condition:
    any of them
}