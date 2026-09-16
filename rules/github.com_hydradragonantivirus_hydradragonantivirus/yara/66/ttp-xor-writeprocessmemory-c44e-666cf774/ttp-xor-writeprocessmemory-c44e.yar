rule TTP_XOR_WriteProcessMemory_c44e {
  strings:
    $key_c44e = { 93 3c [2] a1 1e [2] a7 2b [2] 89 2b [2] b6 37 }

  condition:
    any of them
}