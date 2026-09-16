rule TTP_XOR_WriteProcessMemory_be5b {
  strings:
    $key_be5b = { e9 29 [2] db 0b [2] dd 3e [2] f3 3e [2] cc 22 }

  condition:
    any of them
}