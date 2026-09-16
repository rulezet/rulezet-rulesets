rule TTP_XOR_WriteProcessMemory_d460 {
  strings:
    $key_d460 = { 83 12 [2] b1 30 [2] b7 05 [2] 99 05 [2] a6 19 }

  condition:
    any of them
}