rule TTP_XOR_WriteProcessMemory_8c7e {
  strings:
    $key_8c7e = { db 0c [2] e9 2e [2] ef 1b [2] c1 1b [2] fe 07 }

  condition:
    any of them
}