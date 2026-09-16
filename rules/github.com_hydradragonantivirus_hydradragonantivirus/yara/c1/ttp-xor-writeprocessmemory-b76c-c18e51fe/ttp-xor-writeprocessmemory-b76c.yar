rule TTP_XOR_WriteProcessMemory_b76c {
  strings:
    $key_b76c = { e0 1e [2] d2 3c [2] d4 09 [2] fa 09 [2] c5 15 }

  condition:
    any of them
}