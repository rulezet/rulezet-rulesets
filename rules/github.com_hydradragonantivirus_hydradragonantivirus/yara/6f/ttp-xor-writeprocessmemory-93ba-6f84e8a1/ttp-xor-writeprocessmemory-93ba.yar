rule TTP_XOR_WriteProcessMemory_93ba {
  strings:
    $key_93ba = { c4 c8 [2] f6 ea [2] f0 df [2] de df [2] e1 c3 }

  condition:
    any of them
}