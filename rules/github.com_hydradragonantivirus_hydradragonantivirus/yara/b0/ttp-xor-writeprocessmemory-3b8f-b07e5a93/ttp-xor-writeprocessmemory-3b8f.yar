rule TTP_XOR_WriteProcessMemory_3b8f {
  strings:
    $key_3b8f = { 6c fd [2] 5e df [2] 58 ea [2] 76 ea [2] 49 f6 }

  condition:
    any of them
}