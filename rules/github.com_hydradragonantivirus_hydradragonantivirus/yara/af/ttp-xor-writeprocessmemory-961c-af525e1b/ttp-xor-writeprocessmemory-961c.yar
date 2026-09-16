rule TTP_XOR_WriteProcessMemory_961c {
  strings:
    $key_961c = { c1 6e [2] f3 4c [2] f5 79 [2] db 79 [2] e4 65 }

  condition:
    any of them
}