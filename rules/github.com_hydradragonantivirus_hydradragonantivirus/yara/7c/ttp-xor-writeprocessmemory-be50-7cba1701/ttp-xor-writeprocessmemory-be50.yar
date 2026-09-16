rule TTP_XOR_WriteProcessMemory_be50 {
  strings:
    $key_be50 = { e9 22 [2] db 00 [2] dd 35 [2] f3 35 [2] cc 29 }

  condition:
    any of them
}