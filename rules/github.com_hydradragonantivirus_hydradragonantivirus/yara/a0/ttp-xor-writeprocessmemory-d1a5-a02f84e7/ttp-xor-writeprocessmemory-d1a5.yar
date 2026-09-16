rule TTP_XOR_WriteProcessMemory_d1a5 {
  strings:
    $key_d1a5 = { 86 d7 [2] b4 f5 [2] b2 c0 [2] 9c c0 [2] a3 dc }

  condition:
    any of them
}