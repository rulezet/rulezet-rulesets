rule TTP_XOR_WriteProcessMemory_be76 {
  strings:
    $key_be76 = { e9 04 [2] db 26 [2] dd 13 [2] f3 13 [2] cc 0f }

  condition:
    any of them
}