rule TTP_XOR_WriteProcessMemory_2e50 {
  strings:
    $key_2e50 = { 79 22 [2] 4b 00 [2] 4d 35 [2] 63 35 [2] 5c 29 }

  condition:
    any of them
}