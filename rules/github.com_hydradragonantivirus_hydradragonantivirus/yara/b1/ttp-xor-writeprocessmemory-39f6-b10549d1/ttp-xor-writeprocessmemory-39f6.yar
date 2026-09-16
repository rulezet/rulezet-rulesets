rule TTP_XOR_WriteProcessMemory_39f6 {
  strings:
    $key_39f6 = { 6e 84 [2] 5c a6 [2] 5a 93 [2] 74 93 [2] 4b 8f }

  condition:
    any of them
}