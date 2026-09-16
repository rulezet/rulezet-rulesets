rule TTP_XOR_WriteProcessMemory_b47e {
  strings:
    $key_b47e = { e3 0c [2] d1 2e [2] d7 1b [2] f9 1b [2] c6 07 }

  condition:
    any of them
}