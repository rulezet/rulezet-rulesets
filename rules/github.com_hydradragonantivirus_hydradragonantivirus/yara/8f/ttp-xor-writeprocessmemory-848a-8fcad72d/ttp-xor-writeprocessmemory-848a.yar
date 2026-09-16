rule TTP_XOR_WriteProcessMemory_848a {
  strings:
    $key_848a = { d3 f8 [2] e1 da [2] e7 ef [2] c9 ef [2] f6 f3 }

  condition:
    any of them
}