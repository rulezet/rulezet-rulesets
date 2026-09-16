rule TTP_XOR_WriteProcessMemory_c45e {
  strings:
    $key_c45e = { 93 2c [2] a1 0e [2] a7 3b [2] 89 3b [2] b6 27 }

  condition:
    any of them
}