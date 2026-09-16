rule TTP_XOR_WriteProcessMemory_368f {
  strings:
    $key_368f = { 61 fd [2] 53 df [2] 55 ea [2] 7b ea [2] 44 f6 }

  condition:
    any of them
}