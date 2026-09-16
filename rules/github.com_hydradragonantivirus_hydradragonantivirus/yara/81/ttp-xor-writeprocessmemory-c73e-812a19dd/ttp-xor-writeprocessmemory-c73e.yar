rule TTP_XOR_WriteProcessMemory_c73e {
  strings:
    $key_c73e = { 90 4c [2] a2 6e [2] a4 5b [2] 8a 5b [2] b5 47 }

  condition:
    any of them
}