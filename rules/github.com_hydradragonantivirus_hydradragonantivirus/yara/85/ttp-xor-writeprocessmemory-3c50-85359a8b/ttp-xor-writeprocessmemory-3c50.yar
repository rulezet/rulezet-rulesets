rule TTP_XOR_WriteProcessMemory_3c50 {
  strings:
    $key_3c50 = { 6b 22 [2] 59 00 [2] 5f 35 [2] 71 35 [2] 4e 29 }

  condition:
    any of them
}