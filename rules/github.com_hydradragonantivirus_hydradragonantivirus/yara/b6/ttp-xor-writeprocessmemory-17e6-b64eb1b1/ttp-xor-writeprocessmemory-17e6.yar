rule TTP_XOR_WriteProcessMemory_17e6 {
  strings:
    $key_17e6 = { 40 94 [2] 72 b6 [2] 74 83 [2] 5a 83 [2] 65 9f }

  condition:
    any of them
}