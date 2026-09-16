rule TTP_XOR_WriteProcessMemory_816f {
  strings:
    $key_816f = { d6 1d [2] e4 3f [2] e2 0a [2] cc 0a [2] f3 16 }

  condition:
    any of them
}