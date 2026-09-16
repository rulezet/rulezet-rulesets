rule TTP_XOR_WriteProcessMemory_828f {
  strings:
    $key_828f = { d5 fd [2] e7 df [2] e1 ea [2] cf ea [2] f0 f6 }

  condition:
    any of them
}