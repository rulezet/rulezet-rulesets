rule TTP_XOR_WriteProcessMemory_64c1 {
  strings:
    $key_64c1 = { 33 b3 [2] 01 91 [2] 07 a4 [2] 29 a4 [2] 16 b8 }

  condition:
    any of them
}