rule TTP_XOR_WriteProcessMemory_900e {
  strings:
    $key_900e = { c7 7c [2] f5 5e [2] f3 6b [2] dd 6b [2] e2 77 }

  condition:
    any of them
}