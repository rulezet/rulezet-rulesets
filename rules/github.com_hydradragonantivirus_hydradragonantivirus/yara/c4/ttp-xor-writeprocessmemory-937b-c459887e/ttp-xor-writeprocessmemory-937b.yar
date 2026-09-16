rule TTP_XOR_WriteProcessMemory_937b {
  strings:
    $key_937b = { c4 09 [2] f6 2b [2] f0 1e [2] de 1e [2] e1 02 }

  condition:
    any of them
}