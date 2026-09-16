rule TTP_XOR_WriteProcessMemory_aa76 {
  strings:
    $key_aa76 = { fd 04 [2] cf 26 [2] c9 13 [2] e7 13 [2] d8 0f }

  condition:
    any of them
}