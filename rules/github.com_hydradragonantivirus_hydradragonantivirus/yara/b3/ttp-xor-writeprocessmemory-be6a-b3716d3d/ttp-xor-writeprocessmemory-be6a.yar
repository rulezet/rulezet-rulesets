rule TTP_XOR_WriteProcessMemory_be6a {
  strings:
    $key_be6a = { e9 18 [2] db 3a [2] dd 0f [2] f3 0f [2] cc 13 }

  condition:
    any of them
}