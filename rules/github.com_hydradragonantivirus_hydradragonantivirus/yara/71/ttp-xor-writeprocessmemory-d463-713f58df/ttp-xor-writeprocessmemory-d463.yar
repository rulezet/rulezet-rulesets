rule TTP_XOR_WriteProcessMemory_d463 {
  strings:
    $key_d463 = { 83 11 [2] b1 33 [2] b7 06 [2] 99 06 [2] a6 1a }

  condition:
    any of them
}