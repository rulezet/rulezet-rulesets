rule TTP_XOR_WriteProcessMemory_c35e {
  strings:
    $key_c35e = { 94 2c [2] a6 0e [2] a0 3b [2] 8e 3b [2] b1 27 }

  condition:
    any of them
}