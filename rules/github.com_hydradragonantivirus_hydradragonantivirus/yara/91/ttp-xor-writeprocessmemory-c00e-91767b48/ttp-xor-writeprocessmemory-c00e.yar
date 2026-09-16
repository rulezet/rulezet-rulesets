rule TTP_XOR_WriteProcessMemory_c00e {
  strings:
    $key_c00e = { 97 7c [2] a5 5e [2] a3 6b [2] 8d 6b [2] b2 77 }

  condition:
    any of them
}