rule TTP_XOR_WriteProcessMemory_7210 {
  strings:
    $key_7210 = { 25 62 [2] 17 40 [2] 11 75 [2] 3f 75 [2] 00 69 }

  condition:
    any of them
}