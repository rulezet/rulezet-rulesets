rule TTP_XOR_WriteProcessMemory_c10e {
  strings:
    $key_c10e = { 96 7c [2] a4 5e [2] a2 6b [2] 8c 6b [2] b3 77 }

  condition:
    any of them
}