rule TTP_XOR_WriteProcessMemory_568f {
  strings:
    $key_568f = { 01 fd [2] 33 df [2] 35 ea [2] 1b ea [2] 24 f6 }

  condition:
    any of them
}