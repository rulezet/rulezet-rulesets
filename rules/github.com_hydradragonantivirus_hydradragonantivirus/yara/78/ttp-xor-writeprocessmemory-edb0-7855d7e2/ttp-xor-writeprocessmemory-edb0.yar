rule TTP_XOR_WriteProcessMemory_edb0 {
  strings:
    $key_edb0 = { ba c2 [2] 88 e0 [2] 8e d5 [2] a0 d5 [2] 9f c9 }

  condition:
    any of them
}