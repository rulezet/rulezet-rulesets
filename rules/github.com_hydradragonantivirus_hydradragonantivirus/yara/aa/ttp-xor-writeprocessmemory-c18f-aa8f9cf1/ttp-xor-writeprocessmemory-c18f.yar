rule TTP_XOR_WriteProcessMemory_c18f {
  strings:
    $key_c18f = { 96 fd [2] a4 df [2] a2 ea [2] 8c ea [2] b3 f6 }

  condition:
    any of them
}