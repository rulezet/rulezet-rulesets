rule TTP_XOR_WriteProcessMemory_5f51 {
  strings:
    $key_5f51 = { 08 23 [2] 3a 01 [2] 3c 34 [2] 12 34 [2] 2d 28 }

  condition:
    any of them
}