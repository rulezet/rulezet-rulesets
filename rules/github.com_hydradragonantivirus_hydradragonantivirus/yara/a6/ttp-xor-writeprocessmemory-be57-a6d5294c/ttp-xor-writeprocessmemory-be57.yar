rule TTP_XOR_WriteProcessMemory_be57 {
  strings:
    $key_be57 = { e9 25 [2] db 07 [2] dd 32 [2] f3 32 [2] cc 2e }

  condition:
    any of them
}