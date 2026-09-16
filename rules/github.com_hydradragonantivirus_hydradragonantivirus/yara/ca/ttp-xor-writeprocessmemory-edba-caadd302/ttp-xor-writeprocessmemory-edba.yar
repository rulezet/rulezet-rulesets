rule TTP_XOR_WriteProcessMemory_edba {
  strings:
    $key_edba = { ba c8 [2] 88 ea [2] 8e df [2] a0 df [2] 9f c3 }

  condition:
    any of them
}