rule TTP_XOR_WriteProcessMemory_961d {
  strings:
    $key_961d = { c1 6f [2] f3 4d [2] f5 78 [2] db 78 [2] e4 64 }

  condition:
    any of them
}