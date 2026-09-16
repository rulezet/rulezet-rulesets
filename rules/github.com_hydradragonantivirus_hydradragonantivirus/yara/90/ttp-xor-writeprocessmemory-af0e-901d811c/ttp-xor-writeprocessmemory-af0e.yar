rule TTP_XOR_WriteProcessMemory_af0e {
  strings:
    $key_af0e = { f8 7c [2] ca 5e [2] cc 6b [2] e2 6b [2] dd 77 }

  condition:
    any of them
}