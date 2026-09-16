rule TTP_XOR_WriteProcessMemory_d26b {
  strings:
    $key_d26b = { 85 19 [2] b7 3b [2] b1 0e [2] 9f 0e [2] a0 12 }

  condition:
    any of them
}