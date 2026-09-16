rule TTP_XOR_WriteProcessMemory_c497 {
  strings:
    $key_c497 = { 93 e5 [2] a1 c7 [2] a7 f2 [2] 89 f2 [2] b6 ee }

  condition:
    any of them
}