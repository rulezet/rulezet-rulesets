rule TTP_XOR_WriteProcessMemory_be01 {
  strings:
    $key_be01 = { e9 73 [2] db 51 [2] dd 64 [2] f3 64 [2] cc 78 }

  condition:
    any of them
}