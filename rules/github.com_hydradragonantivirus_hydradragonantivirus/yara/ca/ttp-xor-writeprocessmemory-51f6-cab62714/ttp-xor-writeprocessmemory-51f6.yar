rule TTP_XOR_WriteProcessMemory_51f6 {
  strings:
    $key_51f6 = { 06 84 [2] 34 a6 [2] 32 93 [2] 1c 93 [2] 23 8f }

  condition:
    any of them
}