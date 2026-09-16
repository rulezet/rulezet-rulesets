rule TTP_XOR_WriteProcessMemory_be5a {
  strings:
    $key_be5a = { e9 28 [2] db 0a [2] dd 3f [2] f3 3f [2] cc 23 }

  condition:
    any of them
}