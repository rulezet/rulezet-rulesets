rule TTP_XOR_WriteProcessMemory_be47 {
  strings:
    $key_be47 = { e9 35 [2] db 17 [2] dd 22 [2] f3 22 [2] cc 3e }

  condition:
    any of them
}