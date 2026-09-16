rule TTP_XOR_WriteProcessMemory_4e8f {
  strings:
    $key_4e8f = { 19 fd [2] 2b df [2] 2d ea [2] 03 ea [2] 3c f6 }

  condition:
    any of them
}