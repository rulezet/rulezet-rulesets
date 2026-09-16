rule TTP_XOR_WriteProcessMemory_8eba {
  strings:
    $key_8eba = { d9 c8 [2] eb ea [2] ed df [2] c3 df [2] fc c3 }

  condition:
    any of them
}