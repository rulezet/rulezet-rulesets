rule TTP_XOR_WriteProcessMemory_c03e {
  strings:
    $key_c03e = { 97 4c [2] a5 6e [2] a3 5b [2] 8d 5b [2] b2 47 }

  condition:
    any of them
}