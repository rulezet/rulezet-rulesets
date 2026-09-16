rule TTP_XOR_WriteProcessMemory_be0e {
  strings:
    $key_be0e = { e9 7c [2] db 5e [2] dd 6b [2] f3 6b [2] cc 77 }

  condition:
    any of them
}