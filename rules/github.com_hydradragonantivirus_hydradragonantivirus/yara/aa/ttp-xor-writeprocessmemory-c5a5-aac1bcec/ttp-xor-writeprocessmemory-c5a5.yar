rule TTP_XOR_WriteProcessMemory_c5a5 {
  strings:
    $key_c5a5 = { 92 d7 [2] a0 f5 [2] a6 c0 [2] 88 c0 [2] b7 dc }

  condition:
    any of them
}