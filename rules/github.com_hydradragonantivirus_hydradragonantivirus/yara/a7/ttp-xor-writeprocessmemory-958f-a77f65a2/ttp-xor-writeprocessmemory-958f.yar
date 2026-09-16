rule TTP_XOR_WriteProcessMemory_958f {
  strings:
    $key_958f = { c2 fd [2] f0 df [2] f6 ea [2] d8 ea [2] e7 f6 }

  condition:
    any of them
}