rule TTP_XOR_WriteProcessMemory_0b50 {
  strings:
    $key_0b50 = { 5c 22 [2] 6e 00 [2] 68 35 [2] 46 35 [2] 79 29 }

  condition:
    any of them
}