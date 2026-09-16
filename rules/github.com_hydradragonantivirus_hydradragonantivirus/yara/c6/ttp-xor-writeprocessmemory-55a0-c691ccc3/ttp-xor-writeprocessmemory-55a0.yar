rule TTP_XOR_WriteProcessMemory_55a0 {
  strings:
    $key_55a0 = { 02 d2 [2] 30 f0 [2] 36 c5 [2] 18 c5 [2] 27 d9 }

  condition:
    any of them
}