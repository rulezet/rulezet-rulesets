rule TTP_XOR_WriteProcessMemory_18b0 {
  strings:
    $key_18b0 = { 4f c2 [2] 7d e0 [2] 7b d5 [2] 55 d5 [2] 6a c9 }

  condition:
    any of them
}