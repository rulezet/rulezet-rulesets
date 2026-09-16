rule TTP_XOR_WriteProcessMemory_f7ad {
  strings:
    $key_f7ad = { a0 df [2] 92 fd [2] 94 c8 [2] ba c8 [2] 85 d4 }

  condition:
    any of them
}