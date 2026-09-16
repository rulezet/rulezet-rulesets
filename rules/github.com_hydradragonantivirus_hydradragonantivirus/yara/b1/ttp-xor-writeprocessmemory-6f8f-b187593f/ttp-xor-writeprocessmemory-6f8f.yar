rule TTP_XOR_WriteProcessMemory_6f8f {
  strings:
    $key_6f8f = { 38 fd [2] 0a df [2] 0c ea [2] 22 ea [2] 1d f6 }

  condition:
    any of them
}