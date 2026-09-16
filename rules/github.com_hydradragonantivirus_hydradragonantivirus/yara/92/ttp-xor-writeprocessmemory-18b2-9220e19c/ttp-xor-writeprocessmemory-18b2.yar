rule TTP_XOR_WriteProcessMemory_18b2 {
  strings:
    $key_18b2 = { 4f c0 [2] 7d e2 [2] 7b d7 [2] 55 d7 [2] 6a cb }

  condition:
    any of them
}