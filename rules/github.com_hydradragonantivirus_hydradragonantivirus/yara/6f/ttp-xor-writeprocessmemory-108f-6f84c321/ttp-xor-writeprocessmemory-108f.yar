rule TTP_XOR_WriteProcessMemory_108f {
  strings:
    $key_108f = { 47 fd [2] 75 df [2] 73 ea [2] 5d ea [2] 62 f6 }

  condition:
    any of them
}