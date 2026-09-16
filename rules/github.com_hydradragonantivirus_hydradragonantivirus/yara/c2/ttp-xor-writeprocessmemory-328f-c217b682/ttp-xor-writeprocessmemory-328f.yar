rule TTP_XOR_WriteProcessMemory_328f {
  strings:
    $key_328f = { 65 fd [2] 57 df [2] 51 ea [2] 7f ea [2] 40 f6 }

  condition:
    any of them
}