rule TTP_XOR_WriteProcessMemory_b51e {
  strings:
    $key_b51e = { e2 6c [2] d0 4e [2] d6 7b [2] f8 7b [2] c7 67 }

  condition:
    any of them
}