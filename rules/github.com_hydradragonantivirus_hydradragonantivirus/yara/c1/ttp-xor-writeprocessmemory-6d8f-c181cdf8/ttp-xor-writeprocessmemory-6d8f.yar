rule TTP_XOR_WriteProcessMemory_6d8f {
  strings:
    $key_6d8f = { 3a fd [2] 08 df [2] 0e ea [2] 20 ea [2] 1f f6 }

  condition:
    any of them
}