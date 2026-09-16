rule TTP_XOR_WriteProcessMemory_be02 {
  strings:
    $key_be02 = { e9 70 [2] db 52 [2] dd 67 [2] f3 67 [2] cc 7b }

  condition:
    any of them
}