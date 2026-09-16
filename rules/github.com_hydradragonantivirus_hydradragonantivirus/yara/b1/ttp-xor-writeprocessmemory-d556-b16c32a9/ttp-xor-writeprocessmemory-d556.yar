rule TTP_XOR_WriteProcessMemory_d556 {
  strings:
    $key_d556 = { 82 24 [2] b0 06 [2] b6 33 [2] 98 33 [2] a7 2f }

  condition:
    any of them
}