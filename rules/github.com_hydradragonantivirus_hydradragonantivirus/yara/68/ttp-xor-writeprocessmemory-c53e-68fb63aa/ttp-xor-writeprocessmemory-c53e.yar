rule TTP_XOR_WriteProcessMemory_c53e {
  strings:
    $key_c53e = { 92 4c [2] a0 6e [2] a6 5b [2] 88 5b [2] b7 47 }

  condition:
    any of them
}