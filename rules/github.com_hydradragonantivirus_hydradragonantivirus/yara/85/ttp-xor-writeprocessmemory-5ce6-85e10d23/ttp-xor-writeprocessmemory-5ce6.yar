rule TTP_XOR_WriteProcessMemory_5ce6 {
  strings:
    $key_5ce6 = { 0b 94 [2] 39 b6 [2] 3f 83 [2] 11 83 [2] 2e 9f }

  condition:
    any of them
}