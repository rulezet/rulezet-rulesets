rule TTP_XOR_WriteProcessMemory_d377 {
  strings:
    $key_d377 = { 84 05 [2] b6 27 [2] b0 12 [2] 9e 12 [2] a1 0e }

  condition:
    any of them
}