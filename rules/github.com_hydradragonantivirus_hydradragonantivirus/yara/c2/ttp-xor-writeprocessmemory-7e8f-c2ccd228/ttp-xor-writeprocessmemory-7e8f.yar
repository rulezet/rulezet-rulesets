rule TTP_XOR_WriteProcessMemory_7e8f {
  strings:
    $key_7e8f = { 29 fd [2] 1b df [2] 1d ea [2] 33 ea [2] 0c f6 }

  condition:
    any of them
}