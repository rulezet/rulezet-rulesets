rule TTP_XOR_WriteProcessMemory_d465 {
  strings:
    $key_d465 = { 83 17 [2] b1 35 [2] b7 00 [2] 99 00 [2] a6 1c }

  condition:
    any of them
}