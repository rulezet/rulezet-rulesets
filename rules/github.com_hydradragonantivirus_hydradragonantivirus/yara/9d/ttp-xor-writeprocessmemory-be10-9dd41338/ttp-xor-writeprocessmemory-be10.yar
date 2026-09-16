rule TTP_XOR_WriteProcessMemory_be10 {
  strings:
    $key_be10 = { e9 62 [2] db 40 [2] dd 75 [2] f3 75 [2] cc 69 }

  condition:
    any of them
}