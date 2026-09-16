rule TTP_XOR_WriteProcessMemory_b88f {
  strings:
    $key_b88f = { ef fd [2] dd df [2] db ea [2] f5 ea [2] ca f6 }

  condition:
    any of them
}