rule TTP_XOR_WriteProcessMemory_aa62 {
  strings:
    $key_aa62 = { fd 10 [2] cf 32 [2] c9 07 [2] e7 07 [2] d8 1b }

  condition:
    any of them
}