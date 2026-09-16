rule TTP_XOR_WriteProcessMemory_836c {
  strings:
    $key_836c = { d4 1e [2] e6 3c [2] e0 09 [2] ce 09 [2] f1 15 }

  condition:
    any of them
}