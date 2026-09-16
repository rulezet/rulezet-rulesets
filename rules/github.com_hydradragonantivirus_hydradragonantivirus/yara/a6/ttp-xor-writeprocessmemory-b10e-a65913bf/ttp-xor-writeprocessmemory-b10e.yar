rule TTP_XOR_WriteProcessMemory_b10e {
  strings:
    $key_b10e = { e6 7c [2] d4 5e [2] d2 6b [2] fc 6b [2] c3 77 }

  condition:
    any of them
}