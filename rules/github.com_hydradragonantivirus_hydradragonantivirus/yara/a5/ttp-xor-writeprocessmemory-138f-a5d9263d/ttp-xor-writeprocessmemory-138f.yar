rule TTP_XOR_WriteProcessMemory_138f {
  strings:
    $key_138f = { 44 fd [2] 76 df [2] 70 ea [2] 5e ea [2] 61 f6 }

  condition:
    any of them
}