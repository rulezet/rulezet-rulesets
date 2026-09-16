rule TTP_XOR_WriteProcessMemory_6e50 {
  strings:
    $key_6e50 = { 39 22 [2] 0b 00 [2] 0d 35 [2] 23 35 [2] 1c 29 }

  condition:
    any of them
}