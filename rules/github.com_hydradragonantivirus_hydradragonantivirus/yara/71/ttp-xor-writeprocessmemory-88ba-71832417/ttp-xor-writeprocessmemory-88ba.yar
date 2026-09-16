rule TTP_XOR_WriteProcessMemory_88ba {
  strings:
    $key_88ba = { df c8 [2] ed ea [2] eb df [2] c5 df [2] fa c3 }

  condition:
    any of them
}