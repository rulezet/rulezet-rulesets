rule TTP_XOR_WriteProcessMemory_944d {
  strings:
    $key_944d = { c3 3f [2] f1 1d [2] f7 28 [2] d9 28 [2] e6 34 }

  condition:
    any of them
}