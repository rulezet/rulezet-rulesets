rule TTP_XOR_WriteProcessMemory_be19 {
  strings:
    $key_be19 = { e9 6b [2] db 49 [2] dd 7c [2] f3 7c [2] cc 60 }

  condition:
    any of them
}