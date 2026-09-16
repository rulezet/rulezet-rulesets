rule TTP_XOR_WriteProcessMemory_d14e {
  strings:
    $key_d14e = { 86 3c [2] b4 1e [2] b2 2b [2] 9c 2b [2] a3 37 }

  condition:
    any of them
}