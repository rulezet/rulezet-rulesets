rule TTP_XOR_WriteProcessMemory_be67 {
  strings:
    $key_be67 = { e9 15 [2] db 37 [2] dd 02 [2] f3 02 [2] cc 1e }

  condition:
    any of them
}