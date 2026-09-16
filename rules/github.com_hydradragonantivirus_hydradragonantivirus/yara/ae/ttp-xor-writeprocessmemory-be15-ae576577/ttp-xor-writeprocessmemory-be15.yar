rule TTP_XOR_WriteProcessMemory_be15 {
  strings:
    $key_be15 = { e9 67 [2] db 45 [2] dd 70 [2] f3 70 [2] cc 6c }

  condition:
    any of them
}