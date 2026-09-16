rule TTP_XOR_WriteProcessMemory_0e8f {
  strings:
    $key_0e8f = { 59 fd [2] 6b df [2] 6d ea [2] 43 ea [2] 7c f6 }

  condition:
    any of them
}