rule TTP_XOR_WriteProcessMemory_964d {
  strings:
    $key_964d = { c1 3f [2] f3 1d [2] f5 28 [2] db 28 [2] e4 34 }

  condition:
    any of them
}