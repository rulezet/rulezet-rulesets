rule TTP_XOR_WriteProcessMemory_be4c {
  strings:
    $key_be4c = { e9 3e [2] db 1c [2] dd 29 [2] f3 29 [2] cc 35 }

  condition:
    any of them
}