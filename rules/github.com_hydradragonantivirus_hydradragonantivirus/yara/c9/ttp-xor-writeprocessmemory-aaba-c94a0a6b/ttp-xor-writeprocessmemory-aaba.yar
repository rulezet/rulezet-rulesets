rule TTP_XOR_WriteProcessMemory_aaba {
  strings:
    $key_aaba = { fd c8 [2] cf ea [2] c9 df [2] e7 df [2] d8 c3 }

  condition:
    any of them
}