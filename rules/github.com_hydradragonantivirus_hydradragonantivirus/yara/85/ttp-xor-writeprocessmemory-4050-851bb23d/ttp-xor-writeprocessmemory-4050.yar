rule TTP_XOR_WriteProcessMemory_4050 {
  strings:
    $key_4050 = { 17 22 [2] 25 00 [2] 23 35 [2] 0d 35 [2] 32 29 }

  condition:
    any of them
}