rule TTP_XOR_WriteProcessMemory_be09 {
  strings:
    $key_be09 = { e9 7b [2] db 59 [2] dd 6c [2] f3 6c [2] cc 70 }

  condition:
    any of them
}