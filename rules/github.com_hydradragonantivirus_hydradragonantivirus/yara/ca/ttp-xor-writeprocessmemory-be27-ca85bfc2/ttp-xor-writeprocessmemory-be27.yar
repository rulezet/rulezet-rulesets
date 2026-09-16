rule TTP_XOR_WriteProcessMemory_be27 {
  strings:
    $key_be27 = { e9 55 [2] db 77 [2] dd 42 [2] f3 42 [2] cc 5e }

  condition:
    any of them
}