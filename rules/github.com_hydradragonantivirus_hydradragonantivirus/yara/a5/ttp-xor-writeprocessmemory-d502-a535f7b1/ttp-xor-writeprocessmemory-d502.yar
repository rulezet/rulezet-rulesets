rule TTP_XOR_WriteProcessMemory_d502 {
  strings:
    $key_d502 = { 82 70 [2] b0 52 [2] b6 67 [2] 98 67 [2] a7 7b }

  condition:
    any of them
}