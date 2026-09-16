rule TTP_XOR_WriteProcessMemory_be26 {
  strings:
    $key_be26 = { e9 54 [2] db 76 [2] dd 43 [2] f3 43 [2] cc 5f }

  condition:
    any of them
}