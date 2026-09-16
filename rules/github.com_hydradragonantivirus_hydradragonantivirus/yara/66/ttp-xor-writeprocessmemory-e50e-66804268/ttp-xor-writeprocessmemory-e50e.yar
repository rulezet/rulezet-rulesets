rule TTP_XOR_WriteProcessMemory_e50e {
  strings:
    $key_e50e = { b2 7c [2] 80 5e [2] 86 6b [2] a8 6b [2] 97 77 }

  condition:
    any of them
}