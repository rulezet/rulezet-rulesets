rule TTP_XOR_WriteProcessMemory_d050 {
  strings:
    $key_d050 = { 87 22 [2] b5 00 [2] b3 35 [2] 9d 35 [2] a2 29 }

  condition:
    any of them
}