rule TTP_XOR_WriteProcessMemory_0b10 {
  strings:
    $key_0b10 = { 5c 62 [2] 6e 40 [2] 68 75 [2] 46 75 [2] 79 69 }

  condition:
    any of them
}