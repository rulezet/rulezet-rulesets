rule TTP_XOR_WriteProcessMemory_d265 {
  strings:
    $key_d265 = { 85 17 [2] b7 35 [2] b1 00 [2] 9f 00 [2] a0 1c }

  condition:
    any of them
}