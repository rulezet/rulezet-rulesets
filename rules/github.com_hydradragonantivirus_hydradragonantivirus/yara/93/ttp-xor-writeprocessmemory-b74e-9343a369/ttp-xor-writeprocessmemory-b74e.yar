rule TTP_XOR_WriteProcessMemory_b74e {
  strings:
    $key_b74e = { e0 3c [2] d2 1e [2] d4 2b [2] fa 2b [2] c5 37 }

  condition:
    any of them
}