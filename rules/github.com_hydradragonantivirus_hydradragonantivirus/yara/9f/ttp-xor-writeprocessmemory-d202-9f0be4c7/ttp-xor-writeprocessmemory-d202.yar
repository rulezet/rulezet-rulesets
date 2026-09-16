rule TTP_XOR_WriteProcessMemory_d202 {
  strings:
    $key_d202 = { 85 70 [2] b7 52 [2] b1 67 [2] 9f 67 [2] a0 7b }

  condition:
    any of them
}