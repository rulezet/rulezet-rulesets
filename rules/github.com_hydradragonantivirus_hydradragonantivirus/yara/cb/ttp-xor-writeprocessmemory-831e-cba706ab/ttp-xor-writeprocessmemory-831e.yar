rule TTP_XOR_WriteProcessMemory_831e {
  strings:
    $key_831e = { d4 6c [2] e6 4e [2] e0 7b [2] ce 7b [2] f1 67 }

  condition:
    any of them
}