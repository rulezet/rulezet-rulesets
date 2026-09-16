rule TTP_XOR_WriteProcessMemory_9c8f {
  strings:
    $key_9c8f = { cb fd [2] f9 df [2] ff ea [2] d1 ea [2] ee f6 }

  condition:
    any of them
}