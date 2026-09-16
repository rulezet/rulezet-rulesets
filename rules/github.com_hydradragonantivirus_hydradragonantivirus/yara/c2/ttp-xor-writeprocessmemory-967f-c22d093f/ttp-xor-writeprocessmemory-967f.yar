rule TTP_XOR_WriteProcessMemory_967f {
  strings:
    $key_967f = { c1 0d [2] f3 2f [2] f5 1a [2] db 1a [2] e4 06 }

  condition:
    any of them
}