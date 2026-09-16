rule TTP_XOR_WriteProcessMemory_83ff {
  strings:
    $key_83ff = { d4 8d [2] e6 af [2] e0 9a [2] ce 9a [2] f1 86 }

  condition:
    any of them
}