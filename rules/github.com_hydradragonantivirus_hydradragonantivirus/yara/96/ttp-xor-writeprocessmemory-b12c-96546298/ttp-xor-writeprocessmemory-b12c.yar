rule TTP_XOR_WriteProcessMemory_b12c {
  strings:
    $key_b12c = { e6 5e [2] d4 7c [2] d2 49 [2] fc 49 [2] c3 55 }

  condition:
    any of them
}