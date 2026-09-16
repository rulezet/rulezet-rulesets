rule TTP_XOR_WriteProcessMemory_d88f {
  strings:
    $key_d88f = { 8f fd [2] bd df [2] bb ea [2] 95 ea [2] aa f6 }

  condition:
    any of them
}