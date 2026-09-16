rule TTP_XOR_WriteProcessMemory_aa52 {
  strings:
    $key_aa52 = { fd 20 [2] cf 02 [2] c9 37 [2] e7 37 [2] d8 2b }

  condition:
    any of them
}