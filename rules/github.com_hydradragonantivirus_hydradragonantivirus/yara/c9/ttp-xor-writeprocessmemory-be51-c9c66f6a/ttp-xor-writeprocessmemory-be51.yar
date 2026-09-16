rule TTP_XOR_WriteProcessMemory_be51 {
  strings:
    $key_be51 = { e9 23 [2] db 01 [2] dd 34 [2] f3 34 [2] cc 28 }

  condition:
    any of them
}