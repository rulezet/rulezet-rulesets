rule TTP_XOR_WriteProcessMemory_aad8 {
  strings:
    $key_aad8 = { fd aa [2] cf 88 [2] c9 bd [2] e7 bd [2] d8 a1 }

  condition:
    any of them
}