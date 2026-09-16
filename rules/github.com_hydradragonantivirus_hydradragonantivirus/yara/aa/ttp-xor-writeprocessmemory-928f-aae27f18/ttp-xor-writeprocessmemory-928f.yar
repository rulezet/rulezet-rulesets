rule TTP_XOR_WriteProcessMemory_928f {
  strings:
    $key_928f = { c5 fd [2] f7 df [2] f1 ea [2] df ea [2] e0 f6 }

  condition:
    any of them
}