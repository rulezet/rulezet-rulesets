rule TTP_XOR_WriteProcessMemory_aa72 {
  strings:
    $key_aa72 = { fd 00 [2] cf 22 [2] c9 17 [2] e7 17 [2] d8 0b }

  condition:
    any of them
}