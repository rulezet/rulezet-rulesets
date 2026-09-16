rule TTP_XOR_WriteProcessMemory_aa56 {
  strings:
    $key_aa56 = { fd 24 [2] cf 06 [2] c9 33 [2] e7 33 [2] d8 2f }

  condition:
    any of them
}