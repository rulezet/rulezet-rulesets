rule TTP_XOR_WriteProcessMemory_c23e {
  strings:
    $key_c23e = { 95 4c [2] a7 6e [2] a1 5b [2] 8f 5b [2] b0 47 }

  condition:
    any of them
}