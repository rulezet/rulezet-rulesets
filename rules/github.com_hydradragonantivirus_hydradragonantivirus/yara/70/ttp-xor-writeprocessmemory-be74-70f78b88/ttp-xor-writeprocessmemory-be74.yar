rule TTP_XOR_WriteProcessMemory_be74 {
  strings:
    $key_be74 = { e9 06 [2] db 24 [2] dd 11 [2] f3 11 [2] cc 0d }

  condition:
    any of them
}