rule TTP_XOR_WriteProcessMemory_788f {
  strings:
    $key_788f = { 2f fd [2] 1d df [2] 1b ea [2] 35 ea [2] 0a f6 }

  condition:
    any of them
}