rule TTP_XOR_WriteProcessMemory_cc8f {
  strings:
    $key_cc8f = { 9b fd [2] a9 df [2] af ea [2] 81 ea [2] be f6 }

  condition:
    any of them
}