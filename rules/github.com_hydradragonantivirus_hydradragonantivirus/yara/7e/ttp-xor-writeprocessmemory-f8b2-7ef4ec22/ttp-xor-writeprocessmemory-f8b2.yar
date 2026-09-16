rule TTP_XOR_WriteProcessMemory_f8b2 {
  strings:
    $key_f8b2 = { af c0 [2] 9d e2 [2] 9b d7 [2] b5 d7 [2] 8a cb }

  condition:
    any of them
}