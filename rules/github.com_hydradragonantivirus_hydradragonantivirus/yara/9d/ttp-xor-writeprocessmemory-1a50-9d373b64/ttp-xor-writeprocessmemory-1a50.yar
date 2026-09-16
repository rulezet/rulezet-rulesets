rule TTP_XOR_WriteProcessMemory_1a50 {
  strings:
    $key_1a50 = { 4d 22 [2] 7f 00 [2] 79 35 [2] 57 35 [2] 68 29 }

  condition:
    any of them
}