rule TTP_XOR_WriteProcessMemory_841f {
  strings:
    $key_841f = { d3 6d [2] e1 4f [2] e7 7a [2] c9 7a [2] f6 66 }

  condition:
    any of them
}