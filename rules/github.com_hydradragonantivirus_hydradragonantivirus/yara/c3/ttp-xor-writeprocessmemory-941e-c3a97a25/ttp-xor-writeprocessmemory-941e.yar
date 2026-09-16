rule TTP_XOR_WriteProcessMemory_941e {
  strings:
    $key_941e = { c3 6c [2] f1 4e [2] f7 7b [2] d9 7b [2] e6 67 }

  condition:
    any of them
}