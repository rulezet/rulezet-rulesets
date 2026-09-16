rule TTP_XOR_WriteProcessMemory_c252 {
  strings:
    $key_c252 = { 95 20 [2] a7 02 [2] a1 37 [2] 8f 37 [2] b0 2b }

  condition:
    any of them
}