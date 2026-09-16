rule TTP_XOR_WriteProcessMemory_c9f6 {
  strings:
    $key_c9f6 = { 9e 84 [2] ac a6 [2] aa 93 [2] 84 93 [2] bb 8f }

  condition:
    any of them
}