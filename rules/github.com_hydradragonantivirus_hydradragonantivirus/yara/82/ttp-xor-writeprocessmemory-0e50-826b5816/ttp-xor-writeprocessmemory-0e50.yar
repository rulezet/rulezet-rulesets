rule TTP_XOR_WriteProcessMemory_0e50 {
  strings:
    $key_0e50 = { 59 22 [2] 6b 00 [2] 6d 35 [2] 43 35 [2] 7c 29 }

  condition:
    any of them
}