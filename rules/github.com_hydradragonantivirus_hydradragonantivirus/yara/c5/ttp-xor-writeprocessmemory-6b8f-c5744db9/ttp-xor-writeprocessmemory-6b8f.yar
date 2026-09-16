rule TTP_XOR_WriteProcessMemory_6b8f {
  strings:
    $key_6b8f = { 3c fd [2] 0e df [2] 08 ea [2] 26 ea [2] 19 f6 }

  condition:
    any of them
}