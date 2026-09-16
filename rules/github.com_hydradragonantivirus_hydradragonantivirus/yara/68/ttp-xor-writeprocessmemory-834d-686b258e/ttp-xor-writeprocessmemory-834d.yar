rule TTP_XOR_WriteProcessMemory_834d {
  strings:
    $key_834d = { d4 3f [2] e6 1d [2] e0 28 [2] ce 28 [2] f1 34 }

  condition:
    any of them
}