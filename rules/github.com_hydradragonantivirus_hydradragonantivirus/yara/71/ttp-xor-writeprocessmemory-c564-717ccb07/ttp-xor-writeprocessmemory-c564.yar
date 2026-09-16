rule TTP_XOR_WriteProcessMemory_c564 {
  strings:
    $key_c564 = { 92 16 [2] a0 34 [2] a6 01 [2] 88 01 [2] b7 1d }

  condition:
    any of them
}