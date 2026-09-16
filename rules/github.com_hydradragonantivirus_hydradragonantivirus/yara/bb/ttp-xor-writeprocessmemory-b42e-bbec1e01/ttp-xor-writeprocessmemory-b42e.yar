rule TTP_XOR_WriteProcessMemory_b42e {
  strings:
    $key_b42e = { e3 5c [2] d1 7e [2] d7 4b [2] f9 4b [2] c6 57 }

  condition:
    any of them
}