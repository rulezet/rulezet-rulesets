rule TTP_XOR_WriteProcessMemory_3c8f {
  strings:
    $key_3c8f = { 6b fd [2] 59 df [2] 5f ea [2] 71 ea [2] 4e f6 }

  condition:
    any of them
}