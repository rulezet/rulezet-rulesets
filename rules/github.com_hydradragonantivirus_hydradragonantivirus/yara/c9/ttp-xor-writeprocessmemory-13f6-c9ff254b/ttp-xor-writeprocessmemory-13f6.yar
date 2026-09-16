rule TTP_XOR_WriteProcessMemory_13f6 {
  strings:
    $key_13f6 = { 44 84 [2] 76 a6 [2] 70 93 [2] 5e 93 [2] 61 8f }

  condition:
    any of them
}