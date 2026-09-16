rule TTP_XOR_WriteProcessMemory_af2e {
  strings:
    $key_af2e = { f8 5c [2] ca 7e [2] cc 4b [2] e2 4b [2] dd 57 }

  condition:
    any of them
}