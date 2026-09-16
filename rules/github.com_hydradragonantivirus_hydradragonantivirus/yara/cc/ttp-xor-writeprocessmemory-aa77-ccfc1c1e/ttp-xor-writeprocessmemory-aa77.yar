rule TTP_XOR_WriteProcessMemory_aa77 {
  strings:
    $key_aa77 = { fd 05 [2] cf 27 [2] c9 12 [2] e7 12 [2] d8 0e }

  condition:
    any of them
}