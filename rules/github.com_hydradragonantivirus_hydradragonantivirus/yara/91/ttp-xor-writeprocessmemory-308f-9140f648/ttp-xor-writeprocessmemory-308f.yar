rule TTP_XOR_WriteProcessMemory_308f {
  strings:
    $key_308f = { 67 fd [2] 55 df [2] 53 ea [2] 7d ea [2] 42 f6 }

  condition:
    any of them
}