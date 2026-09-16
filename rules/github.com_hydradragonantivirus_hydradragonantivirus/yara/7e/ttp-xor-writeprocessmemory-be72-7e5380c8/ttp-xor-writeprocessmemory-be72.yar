rule TTP_XOR_WriteProcessMemory_be72 {
  strings:
    $key_be72 = { e9 00 [2] db 22 [2] dd 17 [2] f3 17 [2] cc 0b }

  condition:
    any of them
}