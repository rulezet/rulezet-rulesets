rule TTP_XOR_WriteProcessMemory_be7b {
  strings:
    $key_be7b = { e9 09 [2] db 2b [2] dd 1e [2] f3 1e [2] cc 02 }

  condition:
    any of them
}