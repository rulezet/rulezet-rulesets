rule TTP_XOR_WriteProcessMemory_be59 {
  strings:
    $key_be59 = { e9 2b [2] db 09 [2] dd 3c [2] f3 3c [2] cc 20 }

  condition:
    any of them
}