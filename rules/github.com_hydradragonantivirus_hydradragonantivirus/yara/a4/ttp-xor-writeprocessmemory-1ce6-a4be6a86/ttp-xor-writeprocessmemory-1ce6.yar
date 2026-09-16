rule TTP_XOR_WriteProcessMemory_1ce6 {
  strings:
    $key_1ce6 = { 4b 94 [2] 79 b6 [2] 7f 83 [2] 51 83 [2] 6e 9f }

  condition:
    any of them
}