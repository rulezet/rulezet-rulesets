rule TTP_XOR_WriteProcessMemory_0b41 {
  strings:
    $key_0b41 = { 5c 33 [2] 6e 11 [2] 68 24 [2] 46 24 [2] 79 38 }

  condition:
    any of them
}