rule TTP_XOR_WriteProcessMemory_be5c {
  strings:
    $key_be5c = { e9 2e [2] db 0c [2] dd 39 [2] f3 39 [2] cc 25 }

  condition:
    any of them
}