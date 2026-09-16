rule TTP_XOR_WriteProcessMemory_d5a5 {
  strings:
    $key_d5a5 = { 82 d7 [2] b0 f5 [2] b6 c0 [2] 98 c0 [2] a7 dc }

  condition:
    any of them
}