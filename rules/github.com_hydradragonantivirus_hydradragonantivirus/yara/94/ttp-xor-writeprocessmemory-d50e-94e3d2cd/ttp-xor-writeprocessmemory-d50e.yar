rule TTP_XOR_WriteProcessMemory_d50e {
  strings:
    $key_d50e = { 82 7c [2] b0 5e [2] b6 6b [2] 98 6b [2] a7 77 }

  condition:
    any of them
}