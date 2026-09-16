rule TTP_XOR_WriteProcessMemory_5c8f {
  strings:
    $key_5c8f = { 0b fd [2] 39 df [2] 3f ea [2] 11 ea [2] 2e f6 }

  condition:
    any of them
}