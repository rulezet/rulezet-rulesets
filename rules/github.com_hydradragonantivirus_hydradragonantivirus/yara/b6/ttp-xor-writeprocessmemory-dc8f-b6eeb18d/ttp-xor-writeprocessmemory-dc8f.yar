rule TTP_XOR_WriteProcessMemory_dc8f {
  strings:
    $key_dc8f = { 8b fd [2] b9 df [2] bf ea [2] 91 ea [2] ae f6 }

  condition:
    any of them
}