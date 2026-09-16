rule TTP_XOR_WriteProcessMemory_8b8f {
  strings:
    $key_8b8f = { dc fd [2] ee df [2] e8 ea [2] c6 ea [2] f9 f6 }

  condition:
    any of them
}