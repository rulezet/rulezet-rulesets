rule TTP_XOR_WriteProcessMemory_5d8f {
  strings:
    $key_5d8f = { 0a fd [2] 38 df [2] 3e ea [2] 10 ea [2] 2f f6 }

  condition:
    any of them
}