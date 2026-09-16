rule TTP_XOR_WriteProcessMemory_6400 {
  strings:
    $key_6400 = { 33 72 [2] 01 50 [2] 07 65 [2] 29 65 [2] 16 79 }

  condition:
    any of them
}