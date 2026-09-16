rule TTP_XOR_WriteProcessMemory_0b26 {
  strings:
    $key_0b26 = { 5c 54 [2] 6e 76 [2] 68 43 [2] 46 43 [2] 79 5f }

  condition:
    any of them
}