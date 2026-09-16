rule TTP_XOR_WriteProcessMemory_55d0 {
  strings:
    $key_55d0 = { 02 a2 [2] 30 80 [2] 36 b5 [2] 18 b5 [2] 27 a9 }

  condition:
    any of them
}