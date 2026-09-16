rule TTP_XOR_WriteProcessMemory_408f {
  strings:
    $key_408f = { 17 fd [2] 25 df [2] 23 ea [2] 0d ea [2] 32 f6 }

  condition:
    any of them
}