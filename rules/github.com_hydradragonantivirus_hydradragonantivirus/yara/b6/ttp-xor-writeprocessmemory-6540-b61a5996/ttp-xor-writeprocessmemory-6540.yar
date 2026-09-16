rule TTP_XOR_WriteProcessMemory_6540 {
  strings:
    $key_6540 = { 32 32 [2] 00 10 [2] 06 25 [2] 28 25 [2] 17 39 }

  condition:
    any of them
}