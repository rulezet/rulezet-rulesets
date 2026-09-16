rule TTP_XOR_WriteProcessMemory_aa67 {
  strings:
    $key_aa67 = { fd 15 [2] cf 37 [2] c9 02 [2] e7 02 [2] d8 1e }

  condition:
    any of them
}