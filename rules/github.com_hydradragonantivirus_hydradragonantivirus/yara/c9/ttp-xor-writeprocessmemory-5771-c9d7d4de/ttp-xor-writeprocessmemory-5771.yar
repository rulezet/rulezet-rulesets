rule TTP_XOR_WriteProcessMemory_5771 {
  strings:
    $key_5771 = { 00 03 [2] 32 21 [2] 34 14 [2] 1a 14 [2] 25 08 }

  condition:
    any of them
}