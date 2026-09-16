rule TTP_XOR_WriteProcessMemory_830e {
  strings:
    $key_830e = { d4 7c [2] e6 5e [2] e0 6b [2] ce 6b [2] f1 77 }

  condition:
    any of them
}