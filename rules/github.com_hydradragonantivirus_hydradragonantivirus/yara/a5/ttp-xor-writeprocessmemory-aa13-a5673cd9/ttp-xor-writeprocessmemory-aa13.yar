rule TTP_XOR_WriteProcessMemory_aa13 {
  strings:
    $key_aa13 = { fd 61 [2] cf 43 [2] c9 76 [2] e7 76 [2] d8 6a }

  condition:
    any of them
}