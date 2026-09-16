rule TTP_XOR_WriteProcessMemory_62a0 {
  strings:
    $key_62a0 = { 35 d2 [2] 07 f0 [2] 01 c5 [2] 2f c5 [2] 10 d9 }

  condition:
    any of them
}