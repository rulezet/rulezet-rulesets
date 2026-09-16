rule TTP_XOR_WriteProcessMemory_b56e {
  strings:
    $key_b56e = { e2 1c [2] d0 3e [2] d6 0b [2] f8 0b [2] c7 17 }

  condition:
    any of them
}