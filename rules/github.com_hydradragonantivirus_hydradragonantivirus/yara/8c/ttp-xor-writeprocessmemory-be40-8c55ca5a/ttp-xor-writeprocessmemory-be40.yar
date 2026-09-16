rule TTP_XOR_WriteProcessMemory_be40 {
  strings:
    $key_be40 = { e9 32 [2] db 10 [2] dd 25 [2] f3 25 [2] cc 39 }

  condition:
    any of them
}