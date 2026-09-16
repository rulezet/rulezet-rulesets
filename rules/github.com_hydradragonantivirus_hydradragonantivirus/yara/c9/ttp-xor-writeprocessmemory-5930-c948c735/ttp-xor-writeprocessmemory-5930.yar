rule TTP_XOR_WriteProcessMemory_5930 {
  strings:
    $key_5930 = { 0e 42 [2] 3c 60 [2] 3a 55 [2] 14 55 [2] 2b 49 }

  condition:
    any of them
}