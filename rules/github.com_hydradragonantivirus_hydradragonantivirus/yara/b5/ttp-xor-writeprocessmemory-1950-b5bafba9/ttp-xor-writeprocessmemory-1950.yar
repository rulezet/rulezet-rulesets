rule TTP_XOR_WriteProcessMemory_1950 {
  strings:
    $key_1950 = { 4e 22 [2] 7c 00 [2] 7a 35 [2] 54 35 [2] 6b 29 }

  condition:
    any of them
}