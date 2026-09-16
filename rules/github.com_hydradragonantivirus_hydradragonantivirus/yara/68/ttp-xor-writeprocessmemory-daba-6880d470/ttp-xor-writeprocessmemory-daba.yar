rule TTP_XOR_WriteProcessMemory_daba {
  strings:
    $key_daba = { 8d c8 [2] bf ea [2] b9 df [2] 97 df [2] a8 c3 }

  condition:
    any of them
}