rule TTP_XOR_WriteProcessMemory_c460 {
  strings:
    $key_c460 = { 93 12 [2] a1 30 [2] a7 05 [2] 89 05 [2] b6 19 }

  condition:
    any of them
}