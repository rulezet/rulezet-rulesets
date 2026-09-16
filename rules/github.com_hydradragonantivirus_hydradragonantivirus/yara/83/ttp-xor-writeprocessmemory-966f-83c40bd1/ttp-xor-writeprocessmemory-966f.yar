rule TTP_XOR_WriteProcessMemory_966f {
  strings:
    $key_966f = { c1 1d [2] f3 3f [2] f5 0a [2] db 0a [2] e4 16 }

  condition:
    any of them
}