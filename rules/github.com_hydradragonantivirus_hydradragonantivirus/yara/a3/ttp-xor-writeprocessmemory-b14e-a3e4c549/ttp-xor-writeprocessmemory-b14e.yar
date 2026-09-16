rule TTP_XOR_WriteProcessMemory_b14e {
  strings:
    $key_b14e = { e6 3c [2] d4 1e [2] d2 2b [2] fc 2b [2] c3 37 }

  condition:
    any of them
}