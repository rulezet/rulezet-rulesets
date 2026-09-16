rule TTP_XOR_WriteProcessMemory_c12e {
  strings:
    $key_c12e = { 96 5c [2] a4 7e [2] a2 4b [2] 8c 4b [2] b3 57 }

  condition:
    any of them
}