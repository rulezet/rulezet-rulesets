rule TTP_XOR_WriteProcessMemory_be12 {
  strings:
    $key_be12 = { e9 60 [2] db 42 [2] dd 77 [2] f3 77 [2] cc 6b }

  condition:
    any of them
}