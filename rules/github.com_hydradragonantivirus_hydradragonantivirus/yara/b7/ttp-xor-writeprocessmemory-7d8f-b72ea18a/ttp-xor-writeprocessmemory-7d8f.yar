rule TTP_XOR_WriteProcessMemory_7d8f {
  strings:
    $key_7d8f = { 2a fd [2] 18 df [2] 1e ea [2] 30 ea [2] 0f f6 }

  condition:
    any of them
}