rule TTP_XOR_WriteProcessMemory_836b {
  strings:
    $key_836b = { d4 19 [2] e6 3b [2] e0 0e [2] ce 0e [2] f1 12 }

  condition:
    any of them
}