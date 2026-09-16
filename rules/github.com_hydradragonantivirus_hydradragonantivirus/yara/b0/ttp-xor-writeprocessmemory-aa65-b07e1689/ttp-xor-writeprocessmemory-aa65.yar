rule TTP_XOR_WriteProcessMemory_aa65 {
  strings:
    $key_aa65 = { fd 17 [2] cf 35 [2] c9 00 [2] e7 00 [2] d8 1c }

  condition:
    any of them
}