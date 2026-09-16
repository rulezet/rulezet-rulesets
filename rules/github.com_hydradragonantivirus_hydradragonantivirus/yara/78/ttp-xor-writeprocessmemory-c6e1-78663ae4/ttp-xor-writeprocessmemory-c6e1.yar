rule TTP_XOR_WriteProcessMemory_c6e1 {
  strings:
    $key_c6e1 = { 91 93 [2] a3 b1 [2] a5 84 [2] 8b 84 [2] b4 98 }

  condition:
    any of them
}