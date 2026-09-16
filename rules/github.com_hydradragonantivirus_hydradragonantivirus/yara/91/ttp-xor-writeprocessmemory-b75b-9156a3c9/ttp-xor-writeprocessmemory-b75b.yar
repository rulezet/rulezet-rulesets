rule TTP_XOR_WriteProcessMemory_b75b {
  strings:
    $key_b75b = { e0 29 [2] d2 0b [2] d4 3e [2] fa 3e [2] c5 22 }

  condition:
    any of them
}