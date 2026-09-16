rule TTP_XOR_WriteProcessMemory_7c8f {
  strings:
    $key_7c8f = { 2b fd [2] 19 df [2] 1f ea [2] 31 ea [2] 0e f6 }

  condition:
    any of them
}