rule TTP_XOR_WriteProcessMemory_c14e {
  strings:
    $key_c14e = { 96 3c [2] a4 1e [2] a2 2b [2] 8c 2b [2] b3 37 }

  condition:
    any of them
}