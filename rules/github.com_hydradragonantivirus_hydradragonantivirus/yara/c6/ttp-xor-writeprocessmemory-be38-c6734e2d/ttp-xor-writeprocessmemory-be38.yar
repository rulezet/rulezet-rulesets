rule TTP_XOR_WriteProcessMemory_be38 {
  strings:
    $key_be38 = { e9 4a [2] db 68 [2] dd 5d [2] f3 5d [2] cc 41 }

  condition:
    any of them
}