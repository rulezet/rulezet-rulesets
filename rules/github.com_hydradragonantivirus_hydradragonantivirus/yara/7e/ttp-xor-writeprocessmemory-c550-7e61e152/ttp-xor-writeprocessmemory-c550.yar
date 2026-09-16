rule TTP_XOR_WriteProcessMemory_c550 {
  strings:
    $key_c550 = { 92 22 [2] a0 00 [2] a6 35 [2] 88 35 [2] b7 29 }

  condition:
    any of them
}