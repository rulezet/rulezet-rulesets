rule TTP_XOR_WriteProcessMemory_be3f {
  strings:
    $key_be3f = { e9 4d [2] db 6f [2] dd 5a [2] f3 5a [2] cc 46 }

  condition:
    any of them
}