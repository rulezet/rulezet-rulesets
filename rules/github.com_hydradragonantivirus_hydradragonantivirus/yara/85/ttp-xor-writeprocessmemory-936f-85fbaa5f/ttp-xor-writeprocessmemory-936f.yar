rule TTP_XOR_WriteProcessMemory_936f {
  strings:
    $key_936f = { c4 1d [2] f6 3f [2] f0 0a [2] de 0a [2] e1 16 }

  condition:
    any of them
}