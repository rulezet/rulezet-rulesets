rule TTP_XOR_WriteProcessMemory_be46 {
  strings:
    $key_be46 = { e9 34 [2] db 16 [2] dd 23 [2] f3 23 [2] cc 3f }

  condition:
    any of them
}