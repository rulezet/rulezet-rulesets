rule TTP_XOR_WriteProcessMemory_be5f {
  strings:
    $key_be5f = { e9 2d [2] db 0f [2] dd 3a [2] f3 3a [2] cc 26 }

  condition:
    any of them
}