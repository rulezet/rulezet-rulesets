rule TTP_XOR_WriteProcessMemory_941c {
  strings:
    $key_941c = { c3 6e [2] f1 4c [2] f7 79 [2] d9 79 [2] e6 65 }

  condition:
    any of them
}