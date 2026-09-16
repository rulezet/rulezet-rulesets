rule TTP_XOR_WriteProcessMemory_967d {
  strings:
    $key_967d = { c1 0f [2] f3 2d [2] f5 18 [2] db 18 [2] e4 04 }

  condition:
    any of them
}