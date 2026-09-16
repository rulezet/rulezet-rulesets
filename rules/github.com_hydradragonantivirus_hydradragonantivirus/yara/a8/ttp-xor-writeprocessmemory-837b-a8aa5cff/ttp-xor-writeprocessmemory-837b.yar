rule TTP_XOR_WriteProcessMemory_837b {
  strings:
    $key_837b = { d4 09 [2] e6 2b [2] e0 1e [2] ce 1e [2] f1 02 }

  condition:
    any of them
}