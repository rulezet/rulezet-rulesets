rule TTP_XOR_WriteProcessMemory_956f {
  strings:
    $key_956f = { c2 1d [2] f0 3f [2] f6 0a [2] d8 0a [2] e7 16 }

  condition:
    any of them
}