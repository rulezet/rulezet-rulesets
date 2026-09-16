rule TTP_XOR_WriteProcessMemory_c13e {
  strings:
    $key_c13e = { 96 4c [2] a4 6e [2] a2 5b [2] 8c 5b [2] b3 47 }

  condition:
    any of them
}