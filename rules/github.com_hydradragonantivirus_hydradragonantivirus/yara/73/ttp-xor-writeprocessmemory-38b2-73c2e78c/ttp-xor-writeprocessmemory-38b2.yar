rule TTP_XOR_WriteProcessMemory_38b2 {
  strings:
    $key_38b2 = { 6f c0 [2] 5d e2 [2] 5b d7 [2] 75 d7 [2] 4a cb }

  condition:
    any of them
}