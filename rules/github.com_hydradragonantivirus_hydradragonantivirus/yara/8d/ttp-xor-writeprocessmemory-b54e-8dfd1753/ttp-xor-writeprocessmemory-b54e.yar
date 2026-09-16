rule TTP_XOR_WriteProcessMemory_b54e {
  strings:
    $key_b54e = { e2 3c [2] d0 1e [2] d6 2b [2] f8 2b [2] c7 37 }

  condition:
    any of them
}