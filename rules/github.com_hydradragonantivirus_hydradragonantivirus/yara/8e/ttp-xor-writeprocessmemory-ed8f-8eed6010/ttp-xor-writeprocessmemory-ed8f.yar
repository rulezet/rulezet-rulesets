rule TTP_XOR_WriteProcessMemory_ed8f {
  strings:
    $key_ed8f = { ba fd [2] 88 df [2] 8e ea [2] a0 ea [2] 9f f6 }

  condition:
    any of them
}