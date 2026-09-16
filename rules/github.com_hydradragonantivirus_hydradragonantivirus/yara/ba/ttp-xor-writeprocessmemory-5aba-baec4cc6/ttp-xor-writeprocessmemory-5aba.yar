rule TTP_XOR_WriteProcessMemory_5aba {
  strings:
    $key_5aba = { 0d c8 [2] 3f ea [2] 39 df [2] 17 df [2] 28 c3 }

  condition:
    any of them
}