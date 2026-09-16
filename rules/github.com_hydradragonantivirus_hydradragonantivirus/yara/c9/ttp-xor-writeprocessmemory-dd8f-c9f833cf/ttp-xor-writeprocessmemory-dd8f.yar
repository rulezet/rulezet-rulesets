rule TTP_XOR_WriteProcessMemory_dd8f {
  strings:
    $key_dd8f = { 8a fd [2] b8 df [2] be ea [2] 90 ea [2] af f6 }

  condition:
    any of them
}