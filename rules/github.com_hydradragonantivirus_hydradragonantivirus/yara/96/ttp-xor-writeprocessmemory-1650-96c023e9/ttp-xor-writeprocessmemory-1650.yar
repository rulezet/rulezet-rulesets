rule TTP_XOR_WriteProcessMemory_1650 {
  strings:
    $key_1650 = { 41 22 [2] 73 00 [2] 75 35 [2] 5b 35 [2] 64 29 }

  condition:
    any of them
}