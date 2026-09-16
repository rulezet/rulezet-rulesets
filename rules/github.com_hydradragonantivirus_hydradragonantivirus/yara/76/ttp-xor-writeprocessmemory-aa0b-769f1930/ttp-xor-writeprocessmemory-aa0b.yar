rule TTP_XOR_WriteProcessMemory_aa0b {
  strings:
    $key_aa0b = { fd 79 [2] cf 5b [2] c9 6e [2] e7 6e [2] d8 72 }

  condition:
    any of them
}