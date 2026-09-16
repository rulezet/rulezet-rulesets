rule TTP_XOR_WriteProcessMemory_aad1 {
  strings:
    $key_aad1 = { fd a3 [2] cf 81 [2] c9 b4 [2] e7 b4 [2] d8 a8 }

  condition:
    any of them
}