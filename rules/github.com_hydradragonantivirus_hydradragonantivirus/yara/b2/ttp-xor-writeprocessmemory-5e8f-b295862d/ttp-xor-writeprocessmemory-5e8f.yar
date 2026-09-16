rule TTP_XOR_WriteProcessMemory_5e8f {
  strings:
    $key_5e8f = { 09 fd [2] 3b df [2] 3d ea [2] 13 ea [2] 2c f6 }

  condition:
    any of them
}