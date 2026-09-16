rule TTP_XOR_WriteProcessMemory_c75e {
  strings:
    $key_c75e = { 90 2c [2] a2 0e [2] a4 3b [2] 8a 3b [2] b5 27 }

  condition:
    any of them
}