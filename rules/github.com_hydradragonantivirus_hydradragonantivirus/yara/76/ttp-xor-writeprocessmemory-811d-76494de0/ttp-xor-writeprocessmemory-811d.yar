rule TTP_XOR_WriteProcessMemory_811d {
  strings:
    $key_811d = { d6 6f [2] e4 4d [2] e2 78 [2] cc 78 [2] f3 64 }

  condition:
    any of them
}