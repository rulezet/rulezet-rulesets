rule TTP_XOR_WriteProcessMemory_be00 {
  strings:
    $key_be00 = { e9 72 [2] db 50 [2] dd 65 [2] f3 65 [2] cc 79 }

  condition:
    any of them
}