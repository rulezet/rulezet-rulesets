rule TTP_XOR_WriteProcessMemory_b15b {
  strings:
    $key_b15b = { e6 29 [2] d4 0b [2] d2 3e [2] fc 3e [2] c3 22 }

  condition:
    any of them
}