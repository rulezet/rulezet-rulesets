rule TTP_XOR_WriteProcessMemory_856f {
  strings:
    $key_856f = { d2 1d [2] e0 3f [2] e6 0a [2] c8 0a [2] f7 16 }

  condition:
    any of them
}