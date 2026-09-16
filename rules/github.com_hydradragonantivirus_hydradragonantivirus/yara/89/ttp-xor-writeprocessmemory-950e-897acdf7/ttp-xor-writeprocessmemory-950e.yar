rule TTP_XOR_WriteProcessMemory_950e {
  strings:
    $key_950e = { c2 7c [2] f0 5e [2] f6 6b [2] d8 6b [2] e7 77 }

  condition:
    any of them
}