rule TTP_XOR_WriteProcessMemory_be11 {
  strings:
    $key_be11 = { e9 63 [2] db 41 [2] dd 74 [2] f3 74 [2] cc 68 }

  condition:
    any of them
}