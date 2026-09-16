rule TTP_XOR_WriteProcessMemory_3aba {
  strings:
    $key_3aba = { 6d c8 [2] 5f ea [2] 59 df [2] 77 df [2] 48 c3 }

  condition:
    any of them
}