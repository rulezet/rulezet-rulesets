rule TTP_XOR_WriteProcessMemory_1f8f {
  strings:
    $key_1f8f = { 48 fd [2] 7a df [2] 7c ea [2] 52 ea [2] 6d f6 }

  condition:
    any of them
}