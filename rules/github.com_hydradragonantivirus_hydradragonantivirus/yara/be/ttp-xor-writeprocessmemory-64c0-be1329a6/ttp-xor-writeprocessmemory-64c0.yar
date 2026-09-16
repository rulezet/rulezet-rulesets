rule TTP_XOR_WriteProcessMemory_64c0 {
  strings:
    $key_64c0 = { 33 b2 [2] 01 90 [2] 07 a5 [2] 29 a5 [2] 16 b9 }

  condition:
    any of them
}