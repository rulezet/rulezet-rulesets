rule TTP_XOR_WriteProcessMemory_832e {
  strings:
    $key_832e = { d4 5c [2] e6 7e [2] e0 4b [2] ce 4b [2] f1 57 }

  condition:
    any of them
}