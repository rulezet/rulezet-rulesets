rule TTP_XOR_WriteProcessMemory_0b79 {
  strings:
    $key_0b79 = { 5c 0b [2] 6e 29 [2] 68 1c [2] 46 1c [2] 79 00 }

  condition:
    any of them
}