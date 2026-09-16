rule TTP_XOR_WriteProcessMemory_834e {
  strings:
    $key_834e = { d4 3c [2] e6 1e [2] e0 2b [2] ce 2b [2] f1 37 }

  condition:
    any of them
}