rule TTP_XOR_WriteProcessMemory_c30e {
  strings:
    $key_c30e = { 94 7c [2] a6 5e [2] a0 6b [2] 8e 6b [2] b1 77 }

  condition:
    any of them
}