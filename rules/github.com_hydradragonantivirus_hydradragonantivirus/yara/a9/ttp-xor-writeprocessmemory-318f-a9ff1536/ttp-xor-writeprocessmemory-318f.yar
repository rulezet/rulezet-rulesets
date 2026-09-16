rule TTP_XOR_WriteProcessMemory_318f {
  strings:
    $key_318f = { 66 fd [2] 54 df [2] 52 ea [2] 7c ea [2] 43 f6 }

  condition:
    any of them
}