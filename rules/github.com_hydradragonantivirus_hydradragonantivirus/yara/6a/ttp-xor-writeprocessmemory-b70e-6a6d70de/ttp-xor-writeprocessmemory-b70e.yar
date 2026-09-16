rule TTP_XOR_WriteProcessMemory_b70e {
  strings:
    $key_b70e = { e0 7c [2] d2 5e [2] d4 6b [2] fa 6b [2] c5 77 }

  condition:
    any of them
}