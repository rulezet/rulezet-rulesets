rule TTP_XOR_WriteProcessMemory_a50e {
  strings:
    $key_a50e = { f2 7c [2] c0 5e [2] c6 6b [2] e8 6b [2] d7 77 }

  condition:
    any of them
}