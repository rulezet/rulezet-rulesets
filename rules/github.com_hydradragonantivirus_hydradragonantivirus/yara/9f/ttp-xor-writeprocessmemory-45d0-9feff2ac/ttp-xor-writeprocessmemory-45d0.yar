rule TTP_XOR_WriteProcessMemory_45d0 {
  strings:
    $key_45d0 = { 12 a2 [2] 20 80 [2] 26 b5 [2] 08 b5 [2] 37 a9 }

  condition:
    any of them
}