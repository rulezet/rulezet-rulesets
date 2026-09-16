rule TTP_XOR_WriteProcessMemory_0b12 {
  strings:
    $key_0b12 = { 5c 60 [2] 6e 42 [2] 68 77 [2] 46 77 [2] 79 6b }

  condition:
    any of them
}