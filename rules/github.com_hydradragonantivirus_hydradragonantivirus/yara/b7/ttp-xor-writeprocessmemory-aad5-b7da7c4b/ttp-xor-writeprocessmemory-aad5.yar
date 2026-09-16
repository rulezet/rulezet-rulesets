rule TTP_XOR_WriteProcessMemory_aad5 {
  strings:
    $key_aad5 = { fd a7 [2] cf 85 [2] c9 b0 [2] e7 b0 [2] d8 ac }

  condition:
    any of them
}