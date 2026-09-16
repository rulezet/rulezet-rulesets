rule TTP_XOR_WriteProcessMemory_08b2 {
  strings:
    $key_08b2 = { 5f c0 [2] 6d e2 [2] 6b d7 [2] 45 d7 [2] 7a cb }

  condition:
    any of them
}