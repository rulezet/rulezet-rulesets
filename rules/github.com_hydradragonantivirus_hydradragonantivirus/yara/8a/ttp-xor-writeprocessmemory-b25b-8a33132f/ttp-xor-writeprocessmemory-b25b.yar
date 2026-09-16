rule TTP_XOR_WriteProcessMemory_b25b {
  strings:
    $key_b25b = { e5 29 [2] d7 0b [2] d1 3e [2] ff 3e [2] c0 22 }

  condition:
    any of them
}