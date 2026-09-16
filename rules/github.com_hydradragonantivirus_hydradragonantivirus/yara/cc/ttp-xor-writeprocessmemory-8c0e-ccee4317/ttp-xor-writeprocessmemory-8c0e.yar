rule TTP_XOR_WriteProcessMemory_8c0e {
  strings:
    $key_8c0e = { db 7c [2] e9 5e [2] ef 6b [2] c1 6b [2] fe 77 }

  condition:
    any of them
}