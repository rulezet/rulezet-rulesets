rule TTP_XOR_WriteProcessMemory_aaa0 {
  strings:
    $key_aaa0 = { fd d2 [2] cf f0 [2] c9 c5 [2] e7 c5 [2] d8 d9 }

  condition:
    any of them
}