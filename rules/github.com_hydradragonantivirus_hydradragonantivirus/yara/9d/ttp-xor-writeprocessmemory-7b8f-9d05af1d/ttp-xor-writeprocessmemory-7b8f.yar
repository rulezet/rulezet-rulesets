rule TTP_XOR_WriteProcessMemory_7b8f {
  strings:
    $key_7b8f = { 2c fd [2] 1e df [2] 18 ea [2] 36 ea [2] 09 f6 }

  condition:
    any of them
}