rule TTP_XOR_WriteProcessMemory_b41e {
  strings:
    $key_b41e = { e3 6c [2] d1 4e [2] d7 7b [2] f9 7b [2] c6 67 }

  condition:
    any of them
}