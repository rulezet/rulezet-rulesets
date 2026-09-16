rule TTP_XOR_WriteProcessMemory_af1e {
  strings:
    $key_af1e = { f8 6c [2] ca 4e [2] cc 7b [2] e2 7b [2] dd 67 }

  condition:
    any of them
}