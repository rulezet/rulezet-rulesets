rule TTP_XOR_WriteProcessMemory_0b00 {
  strings:
    $key_0b00 = { 5c 72 [2] 6e 50 [2] 68 65 [2] 46 65 [2] 79 79 }

  condition:
    any of them
}