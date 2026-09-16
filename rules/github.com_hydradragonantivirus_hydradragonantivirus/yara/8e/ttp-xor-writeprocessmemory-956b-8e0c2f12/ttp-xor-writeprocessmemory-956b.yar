rule TTP_XOR_WriteProcessMemory_956b {
  strings:
    $key_956b = { c2 19 [2] f0 3b [2] f6 0e [2] d8 0e [2] e7 12 }

  condition:
    any of them
}