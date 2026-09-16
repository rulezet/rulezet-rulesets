rule TTP_XOR_WriteProcessMemory_4e50 {
  strings:
    $key_4e50 = { 19 22 [2] 2b 00 [2] 2d 35 [2] 03 35 [2] 3c 29 }

  condition:
    any of them
}