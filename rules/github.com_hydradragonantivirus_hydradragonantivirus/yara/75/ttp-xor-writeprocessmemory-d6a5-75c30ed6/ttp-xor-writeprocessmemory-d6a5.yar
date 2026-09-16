rule TTP_XOR_WriteProcessMemory_d6a5 {
  strings:
    $key_d6a5 = { 81 d7 [2] b3 f5 [2] b5 c0 [2] 9b c0 [2] a4 dc }

  condition:
    any of them
}