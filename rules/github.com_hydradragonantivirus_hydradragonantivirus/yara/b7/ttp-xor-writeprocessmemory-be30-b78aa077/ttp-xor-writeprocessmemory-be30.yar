rule TTP_XOR_WriteProcessMemory_be30 {
  strings:
    $key_be30 = { e9 42 [2] db 60 [2] dd 55 [2] f3 55 [2] cc 49 }

  condition:
    any of them
}