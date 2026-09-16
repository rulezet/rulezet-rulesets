rule TTP_XOR_WriteProcessMemory_821d {
  strings:
    $key_821d = { d5 6f [2] e7 4d [2] e1 78 [2] cf 78 [2] f0 64 }

  condition:
    any of them
}