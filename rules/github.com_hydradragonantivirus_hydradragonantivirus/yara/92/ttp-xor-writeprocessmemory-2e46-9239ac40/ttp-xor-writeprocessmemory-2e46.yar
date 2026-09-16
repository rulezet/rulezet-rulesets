rule TTP_XOR_WriteProcessMemory_2e46 {
  strings:
    $key_2e46 = { 79 34 [2] 4b 16 [2] 4d 23 [2] 63 23 [2] 5c 3f }

  condition:
    any of them
}