rule TTP_XOR_WriteProcessMemory_1e8f {
  strings:
    $key_1e8f = { 49 fd [2] 7b df [2] 7d ea [2] 53 ea [2] 6c f6 }

  condition:
    any of them
}