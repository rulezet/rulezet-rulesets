rule TTP_XOR_WriteProcessMemory_3580 {
  strings:
    $key_3580 = { 62 f2 [2] 50 d0 [2] 56 e5 [2] 78 e5 [2] 47 f9 }

  condition:
    any of them
}