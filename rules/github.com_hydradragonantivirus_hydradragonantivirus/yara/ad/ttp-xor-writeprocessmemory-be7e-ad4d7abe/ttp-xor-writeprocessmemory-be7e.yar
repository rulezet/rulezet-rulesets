rule TTP_XOR_WriteProcessMemory_be7e {
  strings:
    $key_be7e = { e9 0c [2] db 2e [2] dd 1b [2] f3 1b [2] cc 07 }

  condition:
    any of them
}