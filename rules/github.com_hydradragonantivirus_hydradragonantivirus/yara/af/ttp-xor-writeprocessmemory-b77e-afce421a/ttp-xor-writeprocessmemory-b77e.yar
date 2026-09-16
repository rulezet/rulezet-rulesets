rule TTP_XOR_WriteProcessMemory_b77e {
  strings:
    $key_b77e = { e0 0c [2] d2 2e [2] d4 1b [2] fa 1b [2] c5 07 }

  condition:
    any of them
}