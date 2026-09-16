rule TTP_XOR_WriteProcessMemory_5951 {
  strings:
    $key_5951 = { 0e 23 [2] 3c 01 [2] 3a 34 [2] 14 34 [2] 2b 28 }

  condition:
    any of them
}