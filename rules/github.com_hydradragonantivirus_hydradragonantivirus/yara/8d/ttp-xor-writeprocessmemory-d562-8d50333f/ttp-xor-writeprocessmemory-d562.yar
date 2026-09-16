rule TTP_XOR_WriteProcessMemory_d562 {
  strings:
    $key_d562 = { 82 10 [2] b0 32 [2] b6 07 [2] 98 07 [2] a7 1b }

  condition:
    any of them
}