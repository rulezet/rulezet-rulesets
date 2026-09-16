rule TTP_XOR_WriteProcessMemory_936c {
  strings:
    $key_936c = { c4 1e [2] f6 3c [2] f0 09 [2] de 09 [2] e1 15 }

  condition:
    any of them
}