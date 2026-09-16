rule TTP_XOR_WriteProcessMemory_448f {
  strings:
    $key_448f = { 13 fd [2] 21 df [2] 27 ea [2] 09 ea [2] 36 f6 }

  condition:
    any of them
}