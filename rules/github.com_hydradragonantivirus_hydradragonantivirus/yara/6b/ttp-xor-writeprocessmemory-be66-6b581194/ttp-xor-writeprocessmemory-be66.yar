rule TTP_XOR_WriteProcessMemory_be66 {
  strings:
    $key_be66 = { e9 14 [2] db 36 [2] dd 03 [2] f3 03 [2] cc 1f }

  condition:
    any of them
}