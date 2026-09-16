rule TTP_XOR_WriteProcessMemory_be3c {
  strings:
    $key_be3c = { e9 4e [2] db 6c [2] dd 59 [2] f3 59 [2] cc 45 }

  condition:
    any of them
}