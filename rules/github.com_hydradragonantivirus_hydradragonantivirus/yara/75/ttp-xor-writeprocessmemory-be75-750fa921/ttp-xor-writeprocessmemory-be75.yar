rule TTP_XOR_WriteProcessMemory_be75 {
  strings:
    $key_be75 = { e9 07 [2] db 25 [2] dd 10 [2] f3 10 [2] cc 0c }

  condition:
    any of them
}