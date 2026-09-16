rule TTP_XOR_WriteProcessMemory_cd8f {
  strings:
    $key_cd8f = { 9a fd [2] a8 df [2] ae ea [2] 80 ea [2] bf f6 }

  condition:
    any of them
}