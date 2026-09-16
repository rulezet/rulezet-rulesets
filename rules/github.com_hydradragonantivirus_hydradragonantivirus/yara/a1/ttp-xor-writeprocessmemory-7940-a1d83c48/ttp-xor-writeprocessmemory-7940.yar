rule TTP_XOR_WriteProcessMemory_7940 {
  strings:
    $key_7940 = { 2e 32 [2] 1c 10 [2] 1a 25 [2] 34 25 [2] 0b 39 }

  condition:
    any of them
}