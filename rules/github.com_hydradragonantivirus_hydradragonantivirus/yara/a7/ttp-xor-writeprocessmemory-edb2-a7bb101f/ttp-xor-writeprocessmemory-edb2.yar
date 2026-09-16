rule TTP_XOR_WriteProcessMemory_edb2 {
  strings:
    $key_edb2 = { ba c0 [2] 88 e2 [2] 8e d7 [2] a0 d7 [2] 9f cb }

  condition:
    any of them
}