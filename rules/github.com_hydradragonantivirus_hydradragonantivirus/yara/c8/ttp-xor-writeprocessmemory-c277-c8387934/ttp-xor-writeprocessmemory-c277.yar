rule TTP_XOR_WriteProcessMemory_c277 {
  strings:
    $key_c277 = { 95 05 [2] a7 27 [2] a1 12 [2] 8f 12 [2] b0 0e }

  condition:
    any of them
}