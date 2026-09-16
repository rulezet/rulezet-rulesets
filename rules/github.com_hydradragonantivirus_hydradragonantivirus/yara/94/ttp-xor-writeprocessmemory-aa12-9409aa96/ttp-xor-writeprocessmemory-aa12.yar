rule TTP_XOR_WriteProcessMemory_aa12 {
  strings:
    $key_aa12 = { fd 60 [2] cf 42 [2] c9 77 [2] e7 77 [2] d8 6b }

  condition:
    any of them
}