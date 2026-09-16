rule TTP_XOR_WriteProcessMemory_b16e {
  strings:
    $key_b16e = { e6 1c [2] d4 3e [2] d2 0b [2] fc 0b [2] c3 17 }

  condition:
    any of them
}