rule TTP_XOR_WriteProcessMemory_5f8f {
  strings:
    $key_5f8f = { 08 fd [2] 3a df [2] 3c ea [2] 12 ea [2] 2d f6 }

  condition:
    any of them
}