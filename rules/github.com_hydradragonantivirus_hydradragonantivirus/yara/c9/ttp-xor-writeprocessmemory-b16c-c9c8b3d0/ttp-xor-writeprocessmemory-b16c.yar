rule TTP_XOR_WriteProcessMemory_b16c {
  strings:
    $key_b16c = { e6 1e [2] d4 3c [2] d2 09 [2] fc 09 [2] c3 15 }

  condition:
    any of them
}