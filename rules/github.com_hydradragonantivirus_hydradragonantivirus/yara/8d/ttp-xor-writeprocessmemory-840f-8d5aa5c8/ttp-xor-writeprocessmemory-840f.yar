rule TTP_XOR_WriteProcessMemory_840f {
  strings:
    $key_840f = { d3 7d [2] e1 5f [2] e7 6a [2] c9 6a [2] f6 76 }

  condition:
    any of them
}