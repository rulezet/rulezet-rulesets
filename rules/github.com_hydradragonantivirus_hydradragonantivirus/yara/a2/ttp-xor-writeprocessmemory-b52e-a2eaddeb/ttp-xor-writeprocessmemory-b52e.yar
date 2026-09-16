rule TTP_XOR_WriteProcessMemory_b52e {
  strings:
    $key_b52e = { e2 5c [2] d0 7e [2] d6 4b [2] f8 4b [2] c7 57 }

  condition:
    any of them
}