rule TTP_XOR_WriteProcessMemory_f68f {
  strings:
    $key_f68f = { a1 fd [2] 93 df [2] 95 ea [2] bb ea [2] 84 f6 }

  condition:
    any of them
}