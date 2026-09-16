rule TTP_XOR_WriteProcessMemory_4800 {
  strings:
    $key_4800 = { 1f 72 [2] 2d 50 [2] 2b 65 [2] 05 65 [2] 3a 79 }

  condition:
    any of them
}