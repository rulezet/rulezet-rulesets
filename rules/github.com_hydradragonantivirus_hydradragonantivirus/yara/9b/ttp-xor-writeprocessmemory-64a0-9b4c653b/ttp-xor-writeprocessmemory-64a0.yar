rule TTP_XOR_WriteProcessMemory_64a0 {
  strings:
    $key_64a0 = { 33 d2 [2] 01 f0 [2] 07 c5 [2] 29 c5 [2] 16 d9 }

  condition:
    any of them
}