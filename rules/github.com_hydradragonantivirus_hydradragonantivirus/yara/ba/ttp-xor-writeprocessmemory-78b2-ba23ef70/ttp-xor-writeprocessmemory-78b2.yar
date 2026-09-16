rule TTP_XOR_WriteProcessMemory_78b2 {
  strings:
    $key_78b2 = { 2f c0 [2] 1d e2 [2] 1b d7 [2] 35 d7 [2] 0a cb }

  condition:
    any of them
}