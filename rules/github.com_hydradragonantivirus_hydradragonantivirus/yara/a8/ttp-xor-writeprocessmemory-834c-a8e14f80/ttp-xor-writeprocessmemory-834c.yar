rule TTP_XOR_WriteProcessMemory_834c {
  strings:
    $key_834c = { d4 3e [2] e6 1c [2] e0 29 [2] ce 29 [2] f1 35 }

  condition:
    any of them
}