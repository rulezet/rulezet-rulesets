rule TTP_XOR_WriteProcessMemory_805f {
  strings:
    $key_805f = { d7 2d [2] e5 0f [2] e3 3a [2] cd 3a [2] f2 26 }

  condition:
    any of them
}