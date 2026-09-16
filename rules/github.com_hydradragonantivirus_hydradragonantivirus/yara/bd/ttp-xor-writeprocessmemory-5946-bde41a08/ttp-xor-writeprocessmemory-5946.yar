rule TTP_XOR_WriteProcessMemory_5946 {
  strings:
    $key_5946 = { 0e 34 [2] 3c 16 [2] 3a 23 [2] 14 23 [2] 2b 3f }

  condition:
    any of them
}