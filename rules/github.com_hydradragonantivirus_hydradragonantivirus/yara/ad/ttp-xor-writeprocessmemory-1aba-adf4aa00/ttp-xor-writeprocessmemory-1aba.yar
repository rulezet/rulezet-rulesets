rule TTP_XOR_WriteProcessMemory_1aba {
  strings:
    $key_1aba = { 4d c8 [2] 7f ea [2] 79 df [2] 57 df [2] 68 c3 }

  condition:
    any of them
}