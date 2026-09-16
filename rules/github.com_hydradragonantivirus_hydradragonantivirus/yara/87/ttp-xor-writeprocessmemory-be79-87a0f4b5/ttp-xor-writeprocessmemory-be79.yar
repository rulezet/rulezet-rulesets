rule TTP_XOR_WriteProcessMemory_be79 {
  strings:
    $key_be79 = { e9 0b [2] db 29 [2] dd 1c [2] f3 1c [2] cc 00 }

  condition:
    any of them
}