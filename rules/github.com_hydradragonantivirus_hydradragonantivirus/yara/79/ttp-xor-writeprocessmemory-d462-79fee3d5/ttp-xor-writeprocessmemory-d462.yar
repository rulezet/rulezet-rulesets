rule TTP_XOR_WriteProcessMemory_d462 {
  strings:
    $key_d462 = { 83 10 [2] b1 32 [2] b7 07 [2] 99 07 [2] a6 1b }

  condition:
    any of them
}