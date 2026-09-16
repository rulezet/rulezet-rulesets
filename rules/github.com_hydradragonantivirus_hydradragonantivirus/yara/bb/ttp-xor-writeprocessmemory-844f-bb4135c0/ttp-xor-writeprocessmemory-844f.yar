rule TTP_XOR_WriteProcessMemory_844f {
  strings:
    $key_844f = { d3 3d [2] e1 1f [2] e7 2a [2] c9 2a [2] f6 36 }

  condition:
    any of them
}