rule TTP_XOR_WriteProcessMemory_d25e {
  strings:
    $key_d25e = { 85 2c [2] b7 0e [2] b1 3b [2] 9f 3b [2] a0 27 }

  condition:
    any of them
}