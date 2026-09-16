rule TTP_XOR_WriteProcessMemory_be42 {
  strings:
    $key_be42 = { e9 30 [2] db 12 [2] dd 27 [2] f3 27 [2] cc 3b }

  condition:
    any of them
}