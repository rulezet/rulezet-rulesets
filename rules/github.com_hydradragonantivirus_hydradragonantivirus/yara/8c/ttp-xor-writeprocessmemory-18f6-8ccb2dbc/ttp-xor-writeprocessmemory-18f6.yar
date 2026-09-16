rule TTP_XOR_WriteProcessMemory_18f6 {
  strings:
    $key_18f6 = { 4f 84 [2] 7d a6 [2] 7b 93 [2] 55 93 [2] 6a 8f }

  condition:
    any of them
}