rule TTP_XOR_WriteProcessMemory_1250 {
  strings:
    $key_1250 = { 45 22 [2] 77 00 [2] 71 35 [2] 5f 35 [2] 60 29 }

  condition:
    any of them
}