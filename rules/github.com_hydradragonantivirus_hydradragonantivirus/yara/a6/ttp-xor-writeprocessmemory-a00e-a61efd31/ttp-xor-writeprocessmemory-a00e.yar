rule TTP_XOR_WriteProcessMemory_a00e {
  strings:
    $key_a00e = { f7 7c [2] c5 5e [2] c3 6b [2] ed 6b [2] d2 77 }

  condition:
    any of them
}