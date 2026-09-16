rule TTP_XOR_WriteProcessMemory_3940 {
  strings:
    $key_3940 = { 6e 32 [2] 5c 10 [2] 5a 25 [2] 74 25 [2] 4b 39 }

  condition:
    any of them
}