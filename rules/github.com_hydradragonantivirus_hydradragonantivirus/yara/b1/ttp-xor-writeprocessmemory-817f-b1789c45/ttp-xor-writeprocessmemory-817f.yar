rule TTP_XOR_WriteProcessMemory_817f {
  strings:
    $key_817f = { d6 0d [2] e4 2f [2] e2 1a [2] cc 1a [2] f3 06 }

  condition:
    any of them
}