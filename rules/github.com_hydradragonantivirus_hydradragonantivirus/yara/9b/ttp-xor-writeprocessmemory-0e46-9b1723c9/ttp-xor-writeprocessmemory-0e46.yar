rule TTP_XOR_WriteProcessMemory_0e46 {
  strings:
    $key_0e46 = { 59 34 [2] 6b 16 [2] 6d 23 [2] 43 23 [2] 7c 3f }

  condition:
    any of them
}