rule TTP_XOR_WriteProcessMemory_d452 {
  strings:
    $key_d452 = { 83 20 [2] b1 02 [2] b7 37 [2] 99 37 [2] a6 2b }

  condition:
    any of them
}