rule TTP_XOR_WriteProcessMemory_d45e {
  strings:
    $key_d45e = { 83 2c [2] b1 0e [2] b7 3b [2] 99 3b [2] a6 27 }

  condition:
    any of them
}