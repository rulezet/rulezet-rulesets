rule TTP_XOR_WriteProcessMemory_be49 {
  strings:
    $key_be49 = { e9 3b [2] db 19 [2] dd 2c [2] f3 2c [2] cc 30 }

  condition:
    any of them
}