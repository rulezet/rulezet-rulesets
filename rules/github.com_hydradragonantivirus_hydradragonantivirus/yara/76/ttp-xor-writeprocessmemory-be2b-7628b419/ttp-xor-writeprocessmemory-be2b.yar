rule TTP_XOR_WriteProcessMemory_be2b {
  strings:
    $key_be2b = { e9 59 [2] db 7b [2] dd 4e [2] f3 4e [2] cc 52 }

  condition:
    any of them
}