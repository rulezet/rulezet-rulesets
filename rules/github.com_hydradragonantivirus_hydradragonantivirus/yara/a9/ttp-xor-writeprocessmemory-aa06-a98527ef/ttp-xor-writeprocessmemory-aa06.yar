rule TTP_XOR_WriteProcessMemory_aa06 {
  strings:
    $key_aa06 = { fd 74 [2] cf 56 [2] c9 63 [2] e7 63 [2] d8 7f }

  condition:
    any of them
}