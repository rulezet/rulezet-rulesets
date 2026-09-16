rule TTP_XOR_WriteProcessMemory_d750 {
  strings:
    $key_d750 = { 80 22 [2] b2 00 [2] b4 35 [2] 9a 35 [2] a5 29 }

  condition:
    any of them
}