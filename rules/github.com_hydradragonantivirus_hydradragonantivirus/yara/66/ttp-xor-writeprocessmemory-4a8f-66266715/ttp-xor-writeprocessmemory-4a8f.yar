rule TTP_XOR_WriteProcessMemory_4a8f {
  strings:
    $key_4a8f = { 1d fd [2] 2f df [2] 29 ea [2] 07 ea [2] 38 f6 }

  condition:
    any of them
}