rule TTP_XOR_WriteProcessMemory_befc {
  strings:
    $key_befc = { e9 8e [2] db ac [2] dd 99 [2] f3 99 [2] cc 85 }

  condition:
    any of them
}