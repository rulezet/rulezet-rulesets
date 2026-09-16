rule TTP_XOR_WriteProcessMemory_831c {
  strings:
    $key_831c = { d4 6e [2] e6 4c [2] e0 79 [2] ce 79 [2] f1 65 }

  condition:
    any of them
}