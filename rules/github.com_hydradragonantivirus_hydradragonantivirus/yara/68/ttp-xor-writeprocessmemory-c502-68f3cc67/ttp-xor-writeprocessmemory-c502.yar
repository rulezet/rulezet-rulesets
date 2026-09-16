rule TTP_XOR_WriteProcessMemory_c502 {
  strings:
    $key_c502 = { 92 70 [2] a0 52 [2] a6 67 [2] 88 67 [2] b7 7b }

  condition:
    any of them
}