rule TTP_XOR_WriteProcessMemory_821e {
  strings:
    $key_821e = { d5 6c [2] e7 4e [2] e1 7b [2] cf 7b [2] f0 67 }

  condition:
    any of them
}