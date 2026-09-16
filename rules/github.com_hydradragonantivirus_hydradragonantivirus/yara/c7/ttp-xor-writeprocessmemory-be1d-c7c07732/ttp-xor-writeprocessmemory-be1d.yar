rule TTP_XOR_WriteProcessMemory_be1d {
  strings:
    $key_be1d = { e9 6f [2] db 4d [2] dd 78 [2] f3 78 [2] cc 64 }

  condition:
    any of them
}