rule TTP_XOR_WriteProcessMemory_d206 {
  strings:
    $key_d206 = { 85 74 [2] b7 56 [2] b1 63 [2] 9f 63 [2] a0 7f }

  condition:
    any of them
}