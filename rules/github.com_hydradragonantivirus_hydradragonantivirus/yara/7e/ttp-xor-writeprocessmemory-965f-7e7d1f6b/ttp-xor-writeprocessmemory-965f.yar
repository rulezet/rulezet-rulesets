rule TTP_XOR_WriteProcessMemory_965f {
  strings:
    $key_965f = { c1 2d [2] f3 0f [2] f5 3a [2] db 3a [2] e4 26 }

  condition:
    any of them
}