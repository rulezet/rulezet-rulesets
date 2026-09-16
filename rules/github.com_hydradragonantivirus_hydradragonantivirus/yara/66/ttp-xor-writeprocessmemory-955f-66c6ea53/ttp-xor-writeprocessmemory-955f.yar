rule TTP_XOR_WriteProcessMemory_955f {
  strings:
    $key_955f = { c2 2d [2] f0 0f [2] f6 3a [2] d8 3a [2] e7 26 }

  condition:
    any of them
}