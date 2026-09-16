rule TTP_XOR_WriteProcessMemory_be3a {
  strings:
    $key_be3a = { e9 48 [2] db 6a [2] dd 5f [2] f3 5f [2] cc 43 }

  condition:
    any of them
}