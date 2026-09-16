rule TTP_XOR_WriteProcessMemory_be6b {
  strings:
    $key_be6b = { e9 19 [2] db 3b [2] dd 0e [2] f3 0e [2] cc 12 }

  condition:
    any of them
}