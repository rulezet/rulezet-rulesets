rule TTP_XOR_WriteProcessMemory_be58 {
  strings:
    $key_be58 = { e9 2a [2] db 08 [2] dd 3d [2] f3 3d [2] cc 21 }

  condition:
    any of them
}