rule TTP_XOR_WriteProcessMemory_208f {
  strings:
    $key_208f = { 77 fd [2] 45 df [2] 43 ea [2] 6d ea [2] 52 f6 }

  condition:
    any of them
}