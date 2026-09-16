rule TTP_XOR_WriteProcessMemory_c240 {
  strings:
    $key_c240 = { 95 32 [2] a7 10 [2] a1 25 [2] 8f 25 [2] b0 39 }

  condition:
    any of them
}