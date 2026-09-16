rule TTP_XOR_WriteProcessMemory_c7e1 {
  strings:
    $key_c7e1 = { 90 93 [2] a2 b1 [2] a4 84 [2] 8a 84 [2] b5 98 }

  condition:
    any of them
}