rule TTP_XOR_WriteProcessMemory_2250 {
  strings:
    $key_2250 = { 75 22 [2] 47 00 [2] 41 35 [2] 6f 35 [2] 50 29 }

  condition:
    any of them
}