rule TTP_XOR_WriteProcessMemory_942e {
  strings:
    $key_942e = { c3 5c [2] f1 7e [2] f7 4b [2] d9 4b [2] e6 57 }

  condition:
    any of them
}