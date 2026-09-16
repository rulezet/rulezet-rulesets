rule TTP_XOR_WriteProcessMemory_be41 {
  strings:
    $key_be41 = { e9 33 [2] db 11 [2] dd 24 [2] f3 24 [2] cc 38 }

  condition:
    any of them
}