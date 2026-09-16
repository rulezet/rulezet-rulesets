rule TTP_XOR_WriteProcessMemory_5400 {
  strings:
    $key_5400 = { 03 72 [2] 31 50 [2] 37 65 [2] 19 65 [2] 26 79 }

  condition:
    any of them
}