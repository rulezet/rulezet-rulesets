rule TTP_XOR_WriteProcessMemory_baba {
  strings:
    $key_baba = { ed c8 [2] df ea [2] d9 df [2] f7 df [2] c8 c3 }

  condition:
    any of them
}