rule TTP_XOR_WriteProcessMemory_5910 {
  strings:
    $key_5910 = { 0e 62 [2] 3c 40 [2] 3a 75 [2] 14 75 [2] 2b 69 }

  condition:
    any of them
}