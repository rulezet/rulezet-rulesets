rule TTP_XOR_WriteProcessMemory_aad6 {
  strings:
    $key_aad6 = { fd a4 [2] cf 86 [2] c9 b3 [2] e7 b3 [2] d8 af }

  condition:
    any of them
}