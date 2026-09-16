rule TTP_XOR_WriteProcessMemory_b84e {
  strings:
    $key_b84e = { ef 3c [2] dd 1e [2] db 2b [2] f5 2b [2] ca 37 }

  condition:
    any of them
}