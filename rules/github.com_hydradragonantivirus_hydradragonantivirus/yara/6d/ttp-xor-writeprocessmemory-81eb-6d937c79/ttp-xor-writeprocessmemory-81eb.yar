rule TTP_XOR_WriteProcessMemory_81eb {
  strings:
    $key_81eb = { d6 99 [2] e4 bb [2] e2 8e [2] cc 8e [2] f3 92 }

  condition:
    any of them
}