rule TTP_XOR_WriteProcessMemory_d580 {
  strings:
    $key_d580 = { 82 f2 [2] b0 d0 [2] b6 e5 [2] 98 e5 [2] a7 f9 }

  condition:
    any of them
}