rule TTP_XOR_WriteProcessMemory_d250 {
  strings:
    $key_d250 = { 85 22 [2] b7 00 [2] b1 35 [2] 9f 35 [2] a0 29 }

  condition:
    any of them
}