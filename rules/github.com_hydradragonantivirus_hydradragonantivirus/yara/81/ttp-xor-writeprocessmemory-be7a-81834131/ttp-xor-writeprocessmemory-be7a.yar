rule TTP_XOR_WriteProcessMemory_be7a {
  strings:
    $key_be7a = { e9 08 [2] db 2a [2] dd 1f [2] f3 1f [2] cc 03 }

  condition:
    any of them
}