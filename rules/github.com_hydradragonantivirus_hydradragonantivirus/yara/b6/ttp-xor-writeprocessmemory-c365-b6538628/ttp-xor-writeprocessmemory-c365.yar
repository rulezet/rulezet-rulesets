rule TTP_XOR_WriteProcessMemory_c365 {
  strings:
    $key_c365 = { 94 17 [2] a6 35 [2] a0 00 [2] 8e 00 [2] b1 1c }

  condition:
    any of them
}