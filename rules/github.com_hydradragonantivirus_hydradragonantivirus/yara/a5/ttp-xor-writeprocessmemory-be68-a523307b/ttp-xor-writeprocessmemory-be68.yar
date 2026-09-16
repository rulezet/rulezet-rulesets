rule TTP_XOR_WriteProcessMemory_be68 {
  strings:
    $key_be68 = { e9 1a [2] db 38 [2] dd 0d [2] f3 0d [2] cc 11 }

  condition:
    any of them
}