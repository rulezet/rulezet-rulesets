rule TTP_XOR_WriteProcessMemory_b13b {
  strings:
    $key_b13b = { e6 49 [2] d4 6b [2] d2 5e [2] fc 5e [2] c3 42 }

  condition:
    any of them
}