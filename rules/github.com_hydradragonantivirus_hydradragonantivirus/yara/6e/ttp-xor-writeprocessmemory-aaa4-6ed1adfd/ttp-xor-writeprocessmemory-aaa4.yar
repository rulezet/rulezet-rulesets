rule TTP_XOR_WriteProcessMemory_aaa4 {
  strings:
    $key_aaa4 = { fd d6 [2] cf f4 [2] c9 c1 [2] e7 c1 [2] d8 dd }

  condition:
    any of them
}