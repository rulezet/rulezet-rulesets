rule TTP_XOR_WriteProcessMemory_e18f {
  strings:
    $key_e18f = { b6 fd [2] 84 df [2] 82 ea [2] ac ea [2] 93 f6 }

  condition:
    any of them
}