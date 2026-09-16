rule TTP_XOR_WriteProcessMemory_be0b {
  strings:
    $key_be0b = { e9 79 [2] db 5b [2] dd 6e [2] f3 6e [2] cc 72 }

  condition:
    any of them
}