rule TTP_XOR_WriteProcessMemory_af6e {
  strings:
    $key_af6e = { f8 1c [2] ca 3e [2] cc 0b [2] e2 0b [2] dd 17 }

  condition:
    any of them
}