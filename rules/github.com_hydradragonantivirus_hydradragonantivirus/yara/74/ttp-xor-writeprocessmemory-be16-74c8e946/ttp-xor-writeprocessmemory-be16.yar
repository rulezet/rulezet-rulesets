rule TTP_XOR_WriteProcessMemory_be16 {
  strings:
    $key_be16 = { e9 64 [2] db 46 [2] dd 73 [2] f3 73 [2] cc 6f }

  condition:
    any of them
}