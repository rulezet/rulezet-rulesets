rule TTP_XOR_WriteProcessMemory_be63 {
  strings:
    $key_be63 = { e9 11 [2] db 33 [2] dd 06 [2] f3 06 [2] cc 1a }

  condition:
    any of them
}