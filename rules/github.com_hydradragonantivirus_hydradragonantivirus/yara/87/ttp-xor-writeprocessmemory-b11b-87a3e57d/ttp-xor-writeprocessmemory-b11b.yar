rule TTP_XOR_WriteProcessMemory_b11b {
  strings:
    $key_b11b = { e6 69 [2] d4 4b [2] d2 7e [2] fc 7e [2] c3 62 }

  condition:
    any of them
}