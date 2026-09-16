rule TTP_XOR_WriteProcessMemory_be6d {
  strings:
    $key_be6d = { e9 1f [2] db 3d [2] dd 08 [2] f3 08 [2] cc 14 }

  condition:
    any of them
}