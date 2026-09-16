rule TTP_XOR_WriteProcessMemory_7571 {
  strings:
    $key_7571 = { 22 03 [2] 10 21 [2] 16 14 [2] 38 14 [2] 07 08 }

  condition:
    any of them
}