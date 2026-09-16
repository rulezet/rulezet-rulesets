rule TTP_XOR_WriteProcessMemory_aa8b {
  strings:
    $key_aa8b = { fd f9 [2] cf db [2] c9 ee [2] e7 ee [2] d8 f2 }

  condition:
    any of them
}