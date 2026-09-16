rule TTP_XOR_WriteProcessMemory_967c {
  strings:
    $key_967c = { c1 0e [2] f3 2c [2] f5 19 [2] db 19 [2] e4 05 }

  condition:
    any of them
}