rule TTP_XOR_WriteProcessMemory_c340 {
  strings:
    $key_c340 = { 94 32 [2] a6 10 [2] a0 25 [2] 8e 25 [2] b1 39 }

  condition:
    any of them
}