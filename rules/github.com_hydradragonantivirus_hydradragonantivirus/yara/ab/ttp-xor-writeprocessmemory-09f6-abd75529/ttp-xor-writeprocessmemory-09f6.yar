rule TTP_XOR_WriteProcessMemory_09f6 {
  strings:
    $key_09f6 = { 5e 84 [2] 6c a6 [2] 6a 93 [2] 44 93 [2] 7b 8f }

  condition:
    any of them
}