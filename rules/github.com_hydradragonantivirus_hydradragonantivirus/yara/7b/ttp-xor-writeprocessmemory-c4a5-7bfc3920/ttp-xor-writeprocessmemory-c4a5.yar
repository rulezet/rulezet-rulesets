rule TTP_XOR_WriteProcessMemory_c4a5 {
  strings:
    $key_c4a5 = { 93 d7 [2] a1 f5 [2] a7 c0 [2] 89 c0 [2] b6 dc }

  condition:
    any of them
}