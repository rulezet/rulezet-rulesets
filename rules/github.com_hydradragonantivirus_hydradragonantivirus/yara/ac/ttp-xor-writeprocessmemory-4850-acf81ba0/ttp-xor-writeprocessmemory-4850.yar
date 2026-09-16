rule TTP_XOR_WriteProcessMemory_4850 {
  strings:
    $key_4850 = { 1f 22 [2] 2d 00 [2] 2b 35 [2] 05 35 [2] 3a 29 }

  condition:
    any of them
}