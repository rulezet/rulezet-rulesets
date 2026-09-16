rule TTP_XOR_WriteProcessMemory_2246 {
  strings:
    $key_2246 = { 75 34 [2] 47 16 [2] 41 23 [2] 6f 23 [2] 50 3f }

  condition:
    any of them
}