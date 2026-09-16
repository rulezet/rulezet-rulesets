rule TTP_XOR_WriteProcessMemory_5c50 {
  strings:
    $key_5c50 = { 0b 22 [2] 39 00 [2] 3f 35 [2] 11 35 [2] 2e 29 }

  condition:
    any of them
}