rule TTP_XOR_WriteProcessMemory_aa43 {
  strings:
    $key_aa43 = { fd 31 [2] cf 13 [2] c9 26 [2] e7 26 [2] d8 3a }

  condition:
    any of them
}