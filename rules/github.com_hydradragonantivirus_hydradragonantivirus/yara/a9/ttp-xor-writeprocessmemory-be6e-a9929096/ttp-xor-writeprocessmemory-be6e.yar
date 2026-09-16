rule TTP_XOR_WriteProcessMemory_be6e {
  strings:
    $key_be6e = { e9 1c [2] db 3e [2] dd 0b [2] f3 0b [2] cc 17 }

  condition:
    any of them
}