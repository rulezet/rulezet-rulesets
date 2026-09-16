rule TTP_XOR_WriteProcessMemory_d322 {
  strings:
    $key_d322 = { 84 50 [2] b6 72 [2] b0 47 [2] 9e 47 [2] a1 5b }

  condition:
    any of them
}