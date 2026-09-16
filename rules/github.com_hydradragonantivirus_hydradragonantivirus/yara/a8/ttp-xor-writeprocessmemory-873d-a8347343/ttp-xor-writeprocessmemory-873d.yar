rule TTP_XOR_WriteProcessMemory_873d {
  strings:
    $key_873d = { d0 4f [2] e2 6d [2] e4 58 [2] ca 58 [2] f5 44 }

  condition:
    any of them
}