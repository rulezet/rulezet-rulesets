rule TTP_XOR_WriteProcessMemory_aaa7 {
  strings:
    $key_aaa7 = { fd d5 [2] cf f7 [2] c9 c2 [2] e7 c2 [2] d8 de }

  condition:
    any of them
}