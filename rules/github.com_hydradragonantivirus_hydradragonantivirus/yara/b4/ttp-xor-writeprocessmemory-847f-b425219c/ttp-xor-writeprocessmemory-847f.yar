rule TTP_XOR_WriteProcessMemory_847f {
  strings:
    $key_847f = { d3 0d [2] e1 2f [2] e7 1a [2] c9 1a [2] f6 06 }

  condition:
    any of them
}