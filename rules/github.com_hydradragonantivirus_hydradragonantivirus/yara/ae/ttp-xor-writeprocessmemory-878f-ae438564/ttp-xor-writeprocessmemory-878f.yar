rule TTP_XOR_WriteProcessMemory_878f {
  strings:
    $key_878f = { d0 fd [2] e2 df [2] e4 ea [2] ca ea [2] f5 f6 }

  condition:
    any of them
}