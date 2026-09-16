rule TTP_XOR_WriteProcessMemory_37f6 {
  strings:
    $key_37f6 = { 60 84 [2] 52 a6 [2] 54 93 [2] 7a 93 [2] 45 8f }

  condition:
    any of them
}