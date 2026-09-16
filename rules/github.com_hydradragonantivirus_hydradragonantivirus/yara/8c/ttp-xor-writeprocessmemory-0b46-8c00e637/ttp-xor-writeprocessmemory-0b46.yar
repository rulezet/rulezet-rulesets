rule TTP_XOR_WriteProcessMemory_0b46 {
  strings:
    $key_0b46 = { 5c 34 [2] 6e 16 [2] 68 23 [2] 46 23 [2] 79 3f }

  condition:
    any of them
}