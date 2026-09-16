rule TTP_XOR_WriteProcessMemory_10a0 {
  strings:
    $key_10a0 = { 47 d2 [2] 75 f0 [2] 73 c5 [2] 5d c5 [2] 62 d9 }

  condition:
    any of them
}