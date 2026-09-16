rule TTP_XOR_WriteProcessMemory_fb8f {
  strings:
    $key_fb8f = { ac fd [2] 9e df [2] 98 ea [2] b6 ea [2] 89 f6 }

  condition:
    any of them
}