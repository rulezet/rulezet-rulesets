rule TTP_XOR_WriteProcessMemory_518f {
  strings:
    $key_518f = { 06 fd [2] 34 df [2] 32 ea [2] 1c ea [2] 23 f6 }

  condition:
    any of them
}