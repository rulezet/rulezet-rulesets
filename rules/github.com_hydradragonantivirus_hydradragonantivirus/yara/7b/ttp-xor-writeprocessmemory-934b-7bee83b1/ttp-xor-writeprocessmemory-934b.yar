rule TTP_XOR_WriteProcessMemory_934b {
  strings:
    $key_934b = { c4 39 [2] f6 1b [2] f0 2e [2] de 2e [2] e1 32 }

  condition:
    any of them
}