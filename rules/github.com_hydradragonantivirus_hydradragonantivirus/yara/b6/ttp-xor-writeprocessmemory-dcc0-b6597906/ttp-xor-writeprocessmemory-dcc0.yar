rule TTP_XOR_WriteProcessMemory_dcc0 {
  strings:
    $key_dcc0 = { 8b b2 [2] b9 90 [2] bf a5 [2] 91 a5 [2] ae b9 }

  condition:
    any of them
}