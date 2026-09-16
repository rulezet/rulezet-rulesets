rule TTP_XOR_WriteProcessMemory_b82e {
  strings:
    $key_b82e = { ef 5c [2] dd 7e [2] db 4b [2] f5 4b [2] ca 57 }

  condition:
    any of them
}