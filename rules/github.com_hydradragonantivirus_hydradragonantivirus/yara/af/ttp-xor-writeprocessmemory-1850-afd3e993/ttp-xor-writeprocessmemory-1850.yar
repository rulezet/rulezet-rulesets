rule TTP_XOR_WriteProcessMemory_1850 {
  strings:
    $key_1850 = { 4f 22 [2] 7d 00 [2] 7b 35 [2] 55 35 [2] 6a 29 }

  condition:
    any of them
}