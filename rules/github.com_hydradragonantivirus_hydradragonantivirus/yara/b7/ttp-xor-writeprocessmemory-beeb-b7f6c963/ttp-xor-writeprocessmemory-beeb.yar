rule TTP_XOR_WriteProcessMemory_beeb {
  strings:
    $key_beeb = { e9 99 [2] db bb [2] dd 8e [2] f3 8e [2] cc 92 }

  condition:
    any of them
}