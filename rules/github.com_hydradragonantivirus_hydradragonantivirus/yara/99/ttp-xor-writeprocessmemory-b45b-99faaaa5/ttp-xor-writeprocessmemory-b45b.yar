rule TTP_XOR_WriteProcessMemory_b45b {
  strings:
    $key_b45b = { e3 29 [2] d1 0b [2] d7 3e [2] f9 3e [2] c6 22 }

  condition:
    any of them
}