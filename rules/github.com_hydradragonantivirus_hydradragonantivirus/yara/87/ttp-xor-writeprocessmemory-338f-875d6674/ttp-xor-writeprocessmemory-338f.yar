rule TTP_XOR_WriteProcessMemory_338f {
  strings:
    $key_338f = { 64 fd [2] 56 df [2] 50 ea [2] 7e ea [2] 41 f6 }

  condition:
    any of them
}