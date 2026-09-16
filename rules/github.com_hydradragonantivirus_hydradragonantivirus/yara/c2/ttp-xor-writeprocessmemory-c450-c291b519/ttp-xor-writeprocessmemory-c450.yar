rule TTP_XOR_WriteProcessMemory_c450 {
  strings:
    $key_c450 = { 93 22 [2] a1 00 [2] a7 35 [2] 89 35 [2] b6 29 }

  condition:
    any of them
}