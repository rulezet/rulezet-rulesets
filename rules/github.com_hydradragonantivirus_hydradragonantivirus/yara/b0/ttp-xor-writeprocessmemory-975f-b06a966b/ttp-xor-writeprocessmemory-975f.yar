rule TTP_XOR_WriteProcessMemory_975f {
  strings:
    $key_975f = { c0 2d [2] f2 0f [2] f4 3a [2] da 3a [2] e5 26 }

  condition:
    any of them
}