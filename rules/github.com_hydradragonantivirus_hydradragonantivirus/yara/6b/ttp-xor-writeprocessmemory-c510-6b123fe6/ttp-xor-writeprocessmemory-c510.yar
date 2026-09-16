rule TTP_XOR_WriteProcessMemory_c510 {
  strings:
    $key_c510 = { 92 62 [2] a0 40 [2] a6 75 [2] 88 75 [2] b7 69 }

  condition:
    any of them
}