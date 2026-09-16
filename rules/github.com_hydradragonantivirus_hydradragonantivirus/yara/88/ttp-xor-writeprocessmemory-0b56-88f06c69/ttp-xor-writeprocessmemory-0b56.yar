rule TTP_XOR_WriteProcessMemory_0b56 {
  strings:
    $key_0b56 = { 5c 24 [2] 6e 06 [2] 68 33 [2] 46 33 [2] 79 2f }

  condition:
    any of them
}