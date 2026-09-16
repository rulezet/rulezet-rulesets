rule TTP_XOR_WriteProcessMemory_be0d {
  strings:
    $key_be0d = { e9 7f [2] db 5d [2] dd 68 [2] f3 68 [2] cc 74 }

  condition:
    any of them
}