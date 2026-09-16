rule TTP_XOR_WriteProcessMemory_925f {
  strings:
    $key_925f = { c5 2d [2] f7 0f [2] f1 3a [2] df 3a [2] e0 26 }

  condition:
    any of them
}