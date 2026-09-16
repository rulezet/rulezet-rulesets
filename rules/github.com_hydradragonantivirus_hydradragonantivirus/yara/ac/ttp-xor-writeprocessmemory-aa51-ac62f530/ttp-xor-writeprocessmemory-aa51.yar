rule TTP_XOR_WriteProcessMemory_aa51 {
  strings:
    $key_aa51 = { fd 23 [2] cf 01 [2] c9 34 [2] e7 34 [2] d8 28 }

  condition:
    any of them
}