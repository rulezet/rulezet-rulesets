rule TTP_XOR_WriteProcessMemory_d565 {
  strings:
    $key_d565 = { 82 17 [2] b0 35 [2] b6 00 [2] 98 00 [2] a7 1c }

  condition:
    any of them
}