rule TTP_XOR_WriteProcessMemory_6bd0 {
  strings:
    $key_6bd0 = { 3c a2 [2] 0e 80 [2] 08 b5 [2] 26 b5 [2] 19 a9 }

  condition:
    any of them
}