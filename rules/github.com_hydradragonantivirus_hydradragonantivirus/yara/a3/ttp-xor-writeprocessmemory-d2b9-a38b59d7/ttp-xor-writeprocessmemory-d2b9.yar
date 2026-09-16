rule TTP_XOR_WriteProcessMemory_d2b9 {
  strings:
    $key_d2b9 = { 85 cb [2] b7 e9 [2] b1 dc [2] 9f dc [2] a0 c0 }

  condition:
    any of them
}