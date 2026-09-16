rule TTP_XOR_WriteProcessMemory_855f {
  strings:
    $key_855f = { d2 2d [2] e0 0f [2] e6 3a [2] c8 3a [2] f7 26 }

  condition:
    any of them
}