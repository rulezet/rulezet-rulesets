rule TTP_XOR_WriteProcessMemory_4746 {
  strings:
    $key_4746 = { 10 34 [2] 22 16 [2] 24 23 [2] 0a 23 [2] 35 3f }

  condition:
    any of them
}