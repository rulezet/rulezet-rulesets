rule TTP_XOR_WriteProcessMemory_76f6 {
  strings:
    $key_76f6 = { 21 84 [2] 13 a6 [2] 15 93 [2] 3b 93 [2] 04 8f }

  condition:
    any of them
}