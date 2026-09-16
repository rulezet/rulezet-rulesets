rule TTP_XOR_WriteProcessMemory_b57e {
  strings:
    $key_b57e = { e2 0c [2] d0 2e [2] d6 1b [2] f8 1b [2] c7 07 }

  condition:
    any of them
}