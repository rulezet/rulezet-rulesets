rule TTP_XOR_WriteProcessMemory_688f {
  strings:
    $key_688f = { 3f fd [2] 0d df [2] 0b ea [2] 25 ea [2] 1a f6 }

  condition:
    any of them
}